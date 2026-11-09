from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional, Tuple

from .models import (
    CarvedFile,
    EntropyResult,
    FileSignature,
    HashBundle,
    ValidationResult,
)
from .source_reader import SourceReader
from .validators import dispatch

logger = logging.getLogger(__name__)


def try_detect_text(
    file_path: str,
    reader: SourceReader,
    file_size: int,
    file_counter: int,
    compute_hashes: bool = True,
    compute_entropy: bool = True,
) -> Optional[CarvedFile]:
    if file_size < 1 or file_size > 500 * 1024 * 1024:
        return None

    # Ignore known binary extensions
    ext = Path(file_path).suffix.lstrip(".").lower()
    binary_extensions = (
        "jpg", "jpeg", "png", "gif", "bmp", "webp", "tif", "tiff",
        "mp4", "avi", "mkv", "mov", "wmv", "mp3", "wav", "flac", "ogg",
        "exe", "dll", "so", "elf", "sys",
        "zip", "rar", "7z", "gz", "bz2", "tar",
        "pdf", "docx", "xlsx", "pptx", "doc", "xls",
        "db", "sqlite", "pst", "vmdk", "vhd",
    )
    if ext in binary_extensions:
        return None

    sample = reader.read_at(0, min(file_size, 16384))
    if not sample:
        return None

    is_text = False
    for enc in ("utf-8-sig", "utf-8", "utf-16", "cp1256", "latin1"):
        try:
            decoded = sample.decode(enc)
            if "utf-16" not in enc and "\x00" in decoded:
                continue
            printable_count = sum(1 for ch in decoded if ch.isprintable() or ch in "\r\n\t ")
            if len(decoded) > 0 and (printable_count / len(decoded)) >= 0.85:
                is_text = True
                break
        except (UnicodeDecodeError, Exception):
            continue

    if not is_text:
        return None

    sig = FileSignature(
        id="text_plain",
        name="Plain Text",
        description="Text document (ASCII / UTF-8 / Unicode)",
        category="document",
        extensions=["txt", "log", "csv", "md", "ini", "cfg", "json", "xml", "html", "bat", "py", "sql"],
        mime_type="text/plain",
        header=b"",
        max_file_size=500 * 1024 * 1024,
        validator="validate_generic",
        confidence=0.80,
    )

    full_text = reader.read_at(0, min(file_size, 25 * 1024 * 1024))
    hashes = HashBundle.from_bytes(full_text) if compute_hashes else None
    entropy = EntropyResult.from_bytes(full_text) if compute_entropy else None

    return CarvedFile(
        id=file_counter,
        signature=sig,
        start_offset=0,
        end_offset=file_size,
        size=file_size,
        confidence=0.80,
        header_hex="",
        trailer_hex="",
        recovery_status="COMPLETE",
        validation=ValidationResult(True, "Text file detected (Unicode / Plain)", 0.0),
        hashes=hashes,
        entropy=entropy,
        metadata={
            "source_file": file_path,
            "encoding": "unicode_text",
        },
        blocks=[(0, file_size)],
        data=full_text,
        is_embedded=False,
        artifact_type="primary",
    )


def triage_file(
    engine,
    file_path: str,
    reader: SourceReader,
    file_size: int,
) -> Optional[CarvedFile]:
    """Triage a single file: verify header signature, detect extension mismatches, compute hashes."""
    header_sample = reader.read_at(0, 4096)
    if not header_sample:
        return None

    p = Path(file_path)
    ext = p.suffix.lstrip(".").lower()

    matches = engine.sig_db.find_by_header(header_sample, 0)

    sig = None
    if matches:
        for m in matches:
            if ext in m.extensions:
                sig = m
                break
        if not sig:
            sig = matches[0]

    if not sig:
        text_file = try_detect_text(
            file_path,
            reader,
            file_size,
            engine._file_counter + 1,
            engine.compute_hashes,
            engine.compute_entropy,
        )
        if text_file:
            engine._file_counter += 1
            return text_file

        sig = FileSignature(
            id=f"ext_{ext or 'unknown'}",
            name=f"{ext.upper()} File" if ext else "Unknown Binary",
            description=f"File with .{ext} extension" if ext else "Unidentified file",
            category="other",
            extensions=[ext] if ext else ["bin"],
            mime_type="application/octet-stream",
            header=b"",
            validator="validate_generic",
            confidence=0.5,
        )
    validation = dispatch(sig.validator, header_sample)
    conf = sig.confidence + (validation.confidence_boost if validation.is_valid else -0.3)
    conf = max(0.05, min(1.0, conf))

    metadata = engine._extract_metadata(header_sample, sig)
    metadata["source_file"] = file_path
    if ext and sig.extensions and ext not in sig.extensions and sig.id != f"ext_{ext}":
        metadata["extension_mismatch"] = True
        metadata["expected_extension"] = sig.extensions[0]
        metadata["actual_extension"] = ext

    hashes = None
    entropy = None
    full_data = None
    if engine.compute_hashes or engine.compute_entropy:
        read_size = min(file_size, sig.max_file_size)
        full_data = reader.read_at(0, read_size)
        if full_data:
            if engine.compute_hashes:
                hashes = HashBundle.from_bytes(full_data)
            if engine.compute_entropy:
                entropy = EntropyResult.from_bytes(full_data[:65536])

    engine._file_counter += 1
    header_hex = header_sample[: min(len(header_sample), 16)].hex().upper()
    trailer_hex = ""
    recovery_status = "COMPLETE" if validation.is_valid else "PARTIAL"

    logger.info(f"Triage: {p.name} -> {sig.name} ({file_size:,} bytes)")

    return CarvedFile(
        id=engine._file_counter,
        signature=sig,
        start_offset=0,
        end_offset=file_size,
        size=file_size,
        confidence=round(conf, 4),
        header_hex=header_hex,
        trailer_hex=trailer_hex,
        recovery_status=recovery_status,
        validation=validation,
        hashes=hashes,
        entropy=entropy,
        metadata=metadata,
        blocks=[(0, file_size)],
        data=full_data if file_size <= 10 * 1024 * 1024 else None,
        is_embedded=False,
        artifact_type="primary",
    )


def execute_triage_scan(
    engine,
    source_path: str,
    source_type: str,
    max_bytes: Optional[int] = None,
) -> Tuple[List[CarvedFile], Optional[HashBundle], int, int]:
    """Fast triage scan: inspects files as individual units without carving embedded streams."""
    carved: List[CarvedFile] = []
    source_hash: Optional[HashBundle] = None
    bytes_scanned = 0
    blocks_scanned = 0

    try:
        source_type = source_type.lower()
        if source_type == "directory":
            dir_path = Path(source_path)
            if not dir_path.is_dir():
                raise NotADirectoryError(f"Directory not found: {source_path}")
            files = [p for p in dir_path.rglob("*") if p.is_file()]
            for fpath in files:
                if engine._stop[0]:
                    break
                try:
                    with SourceReader(str(fpath)) as f_reader:
                        f_size = f_reader.size
                        if f_size == 0:
                            continue
                        bytes_scanned += f_size
                        blocks_scanned += 1
                        item = triage_file(engine, str(fpath), f_reader, f_size)
                        if item:
                            carved.append(item)
                except Exception as e:
                    engine._errors.append(f"Triage error on {fpath.name}: {e}")
        else:
            with SourceReader(source_path) as reader:
                source_hash = engine._hash_source(reader)
                f_size = reader.size
                bytes_scanned += f_size
                blocks_scanned += 1
                item = triage_file(engine, source_path, reader, f_size)
                if item:
                    carved.append(item)
    except Exception as e:
        engine._errors.append(f"Scan error: {e}")
        engine._log(f"Scan error: {e}")

    return carved, source_hash, bytes_scanned, blocks_scanned
