from __future__ import annotations

import os
import sys
import hashlib
import struct
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("core.engine")

from .models import (
    CarvedFile,
    CustodyEntry,
    EntropyResult,
    HashBundle,
    ScanResult,
    ValidationResult,
    calculate_hashes_from_stream,
)
from .signatures import FileSignature, SignatureDatabase
from .validators import dispatch
from .fragment_recovery import recover_fragmented_candidates
from .image_readers import reader_for_source
from .metadata_extractors import (
    extract_file_metadata,
    extract_basic_metadata,
    extract_advanced_metadata,
)
from .source_detector import detect_source_type, is_physical_drive
from .custody import CustodyManager
from .yara_engine import YaraScanner

from .offset_registry import OffsetRegistry, MAX_OVERLAP_GAP
from .source_reader import SourceReader
from .eof_analyzers import find_file_end, search_trailer, find_pe_end, find_bmp_end
from .triage_scanner import execute_triage_scan, triage_file, try_detect_text
from .source_detector import detect_source_type
from .custody import CustodyManager
from .metadata_extractors import extract_file_metadata, extract_basic_metadata



BLOCK_SIZE = 4096           # 4 KB scanning window stride
READ_AHEAD = 64             # blocks to read into memory buffer (256 KB)
MIN_FILE_SIZE = 64          # bytes — discard tiny false positives



class CarvingEngine:
    """
    Main file-carving coordinator.
    Reads input source block-by-block, matches signatures, validates candidates,
    calculates hashes and Shannon entropy, and tracks chain of custody.
    """

    def __init__(
        self,
        sig_db: SignatureDatabase,
        analyst: str = "analyst",
        compute_hashes: bool = True,
        compute_entropy: bool = True,
        yara_rules_path: str = "",
        stop_flag: Optional[List[bool]] = None,
        progress_cb: Optional[Callable[[int, int, int], None]] = None,
    ):
        self.sig_db = sig_db
        self.analyst = analyst
        self.compute_hashes = compute_hashes
        self.compute_entropy = compute_entropy
        self._stop = stop_flag if stop_flag is not None else [False]
        self._progress_cb = progress_cb or (lambda *_: None)

        self._yara: Optional[YaraScanner] = None
        if yara_rules_path:
            self._yara = YaraScanner(yara_rules_path)

        self._file_counter = 0
        self._registry = OffsetRegistry()
        self.custody = CustodyManager(analyst=self.analyst)
        self._errors: List[str] = []

    def stop(self):
        """Signal the engine to stop scanning."""
        self._stop[0] = True

    def scan(
        self,
        source_path: str,
        source_type: str = "auto",
        max_bytes: Optional[int] = None,
        start_offset: int = 0,
        recover_fragments: bool = False,
        scan_mode: str = "deep",
    ) -> ScanResult:
        """
        Scan a source and return a ScanResult.

        source_type: 'file' | 'directory' | 'disk_image' | 'physical_drive' | 'auto'
        scan_mode: 'deep' | 'triage'
        """
        start_time, source_type = self._prepare_scan(source_path, source_type)
        carved, source_hash, bytes_scanned, blocks_scanned = self._execute_scan(
            source_path, source_type, max_bytes, start_offset, recover_fragments, scan_mode=scan_mode
        )
        return self._finalize_scan(
            source_path, source_type, source_hash, start_time,
            carved, bytes_scanned, blocks_scanned
        )

    def _prepare_scan(self, source_path: str, source_type: str) -> Tuple[datetime, str]:
        """Initialize scan state and detect source type if needed."""
        self._file_counter = 0
        self._registry = OffsetRegistry()
        self.custody.reset()
        self._errors = []

        if source_type == "auto":
            source_type = self._detect_type(source_path)

        start_time = datetime.now(timezone.utc)
        self._log(f"Scan started — source: {source_path} ({source_type})")
        if self._yara and not self._yara.available:
            self._errors.append(f"YARA disabled: {self._yara.error}")

        return start_time, source_type

    def _execute_scan(
        self,
        source_path: str,
        source_type: str,
        max_bytes: Optional[int],
        start_offset: int,
        recover_fragments: bool,
        scan_mode: str = "deep",
    ) -> Tuple[List[CarvedFile], Optional[HashBundle], int, int]:
        """Execute the main scanning loop and return results."""
        if scan_mode == "triage":
            return execute_triage_scan(self, source_path, source_type, max_bytes)

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
                logger.info(f"Directory scan: {len(files)} files discovered in {source_path}")
                max_header_len = max(
                    (len(s.header) + s.header_offset for s in self.sig_db.all),
                    default=16,
                )
                overlap = max_header_len + 16
                for fpath in files:
                    if self._stop[0]:
                        break
                    try:
                        logger.info(f"Scanning target: {fpath.name}")
                        with SourceReader(str(fpath)) as f_reader:
                            f_size = f_reader.size
                            if f_size == 0:
                                continue
                            f_limit = min(max_bytes, f_size) if max_bytes else f_size
                            carved, s_bytes, s_blocks = self._scan_blocks(
                                f_reader, str(fpath), 0, f_limit, overlap, carved
                            )
                            bytes_scanned += s_bytes
                            blocks_scanned += s_blocks

                            file_str = str(fpath)
                            detected_for_this_file = any(
                                c.metadata.get("source_file") == file_str for c in carved
                            )
                            if not detected_for_this_file:
                                text_item = try_detect_text(
                                    file_str,
                                    f_reader,
                                    f_size,
                                    self._file_counter + 1,
                                    self.compute_hashes,
                                    self.compute_entropy,
                                )
                                if text_item:
                                    self._file_counter += 1
                                    if self._yara and text_item.data:
                                        yhits = self._yara.scan_bytes(text_item.data)
                                        if yhits:
                                            text_item.metadata["yara_matches"] = [m.to_dict() for m in yhits]
                                    carved.append(text_item)
                                    logger.info(f"Carved [Plain Text] in {fpath.name} ({f_size:,} bytes)")
                    except Exception as e:
                        self._errors.append(f"Failed scanning file {fpath.name}: {e}")
            else:
                reader_ctx = (
                    reader_for_source(source_path, source_type)
                    if source_type in ("e01", "aff")
                    else SourceReader(source_path)
                )
                with reader_ctx as reader:
                    source_hash = self._hash_source(reader)
                    total_bytes = reader.size if (reader.size and reader.size > 0) else 0
                    if max_bytes:
                        scan_limit = start_offset + max_bytes
                    elif total_bytes > 0:
                        scan_limit = total_bytes
                    else:
                        scan_limit = float("inf")  

                    max_header_len = max(
                        (len(s.header) + s.header_offset for s in self.sig_db.all),
                        default=16,
                    )
                    overlap = max_header_len + 16

                    carved, bytes_scanned, blocks_scanned = self._scan_blocks(
                        reader, source_path, start_offset, scan_limit, overlap, carved
                    )

            if recover_fragments:
                recovered = recover_fragmented_candidates(carved)
                if recovered:
                    carved.extend(recovered)
                    self._log(f"Fragment recovery generated {len(recovered)} candidate files")

        except PermissionError as e:
            msg = f"Permission denied: {e} — run as Administrator/root"
            self._errors.append(msg)
            self._log(msg)
        except FileNotFoundError as e:
            msg = f"Source not found: {e}"
            self._errors.append(msg)
            self._log(msg)
        except Exception as e:
            msg = f"Scan error: {e}"
            self._errors.append(msg)
            self._log(msg)

        return carved, source_hash, bytes_scanned, blocks_scanned

    def _hash_source(self, reader) -> Optional[HashBundle]:
        """Hash the source for chain of custody."""
        source_hash = reader.hash_source()
        if source_hash:
            self._log(
                f"Source hash — MD5:{source_hash.md5[:8]}... "
                f"SHA256:{source_hash.sha256[:8]}...",
                source_hash=source_hash.sha256,
            )
        return source_hash

    def _scan_blocks(
        self,
        reader,
        source_path: str,
        start_offset: int,
        scan_limit: int,
        overlap: int,
        carved: List[CarvedFile],
    ) -> Tuple[List[CarvedFile], int, int]:
        """Scan blocks and return carved files, bytes scanned, and blocks scanned."""
        bytes_scanned = 0
        blocks_scanned = 0
        offset = start_offset

        while offset < scan_limit:
            if self._stop[0]:
                self._log("Scan stopped by user")
                break

            read_size = BLOCK_SIZE + overlap
            block = reader.read_at(offset, read_size)
            if not block:
                break

            hits = self._search_block(block, offset, reader, source_path)
            carved.extend(hits)

            bytes_scanned += len(block)
            blocks_scanned += 1
            offset += BLOCK_SIZE

            if blocks_scanned % 32 == 0:
                cur_total = int(scan_limit) if scan_limit != float("inf") else 0
                cur_pos = min(offset, cur_total) if cur_total > 0 else offset
                self._progress_cb(cur_pos, cur_total, len(carved))

        cur_total = int(scan_limit) if scan_limit != float("inf") else 0
        cur_pos = min(offset, cur_total) if cur_total > 0 else offset
        self._progress_cb(cur_pos, cur_total, len(carved))

        return carved, bytes_scanned, blocks_scanned

    def _finalize_scan(
        self,
        source_path: str,
        source_type: str,
        source_hash: Optional[HashBundle],
        start_time: datetime,
        carved: List[CarvedFile],
        bytes_scanned: int,
        blocks_scanned: int,
    ) -> ScanResult:
        """Finalize scan and return ScanResult."""
        end_time = datetime.now(timezone.utc)
        self._log(
            f"Scan complete — {len(carved)} files found, "
            f"{blocks_scanned} blocks, {bytes_scanned:,} bytes"
        )

        return ScanResult(
            source_path=source_path,
            source_type=source_type,
            source_hash=source_hash,
            start_time=start_time,
            end_time=end_time,
            blocks_scanned=blocks_scanned,
            bytes_scanned=bytes_scanned,
            carved_files=carved,
            custody_log=self.custody.entries,
            errors=list(self._errors),
        )


    def _search_block(
        self,
        block: bytes,
        block_base_offset: int,
        reader: SourceReader,
        source_path: str,
    ) -> List[CarvedFile]:
        found = []
        block_len = len(block)

        for local_off in range(block_len):
            if self._stop[0]:
                break

            matches = self.sig_db.find_by_header(block, local_off)
            for sig in matches:
                abs_offset = block_base_offset + local_off
                carved = self._carve(abs_offset, sig, reader, source_path)
                if carved:
                    found.append(carved)

        return found

    def _carve(
        self,
        start_offset: int,
        sig: FileSignature,
        reader: SourceReader,
        source_path: str,
    ) -> Optional[CarvedFile]:
        end_offset = self._find_end(start_offset, sig, reader)
        if end_offset <= start_offset:
            return None

        size = end_offset - start_offset
        if size < MIN_FILE_SIZE or size > sig.max_file_size * 2:
            return None

        sample_size = min(size, 1024 * 1024)
        sample_data = reader.read_at(start_offset, sample_size)
        if not sample_data:
            return None

        validation = dispatch(sig.validator, sample_data)
        if not validation.is_valid:
            return None

        conf = sig.confidence + validation.confidence_boost
        conf = max(0.05, min(1.0, conf))

        if not self._registry.can_register(start_offset, conf, source_path):
            return None

        full_data: Optional[bytes] = None
        hashes: Optional[HashBundle] = None
        entropy: Optional[EntropyResult] = None

        if self.compute_hashes or self.compute_entropy:
            read_size = min(size, sig.max_file_size)
            if read_size <= len(sample_data):
                full_data = sample_data[:read_size]
            else:
                full_data = reader.read_at(start_offset, read_size)
            if full_data:
                if self.compute_hashes:
                    hashes = HashBundle.from_bytes(full_data)
                if self.compute_entropy:
                    entropy_sample = full_data[:min(65536, len(full_data))]
                    entropy = EntropyResult.from_bytes(entropy_sample)

        metadata = extract_file_metadata(sample_data, sig)
        metadata["source_file"] = source_path
        if self._yara and full_data:
            yara_hits = self._yara.scan_bytes(full_data[: min(len(full_data), 2 * 1024 * 1024)], abs_offset=start_offset)
            if yara_hits:
                metadata["yara_matches"] = [m.to_dict() for m in yara_hits]

        source_file_ext = Path(source_path).suffix.lstrip(".").lower()
        is_physical_or_image = (
            source_path.startswith("\\\\.\\")
            or source_file_ext in ("dd", "raw", "img", "bin", "e01", "ex01", "aff")
        )
        if is_physical_or_image:
            artifact_type = "recovered"
            is_embedded = False
        elif start_offset > 0:
            is_embedded = True
            artifact_type = "embedded"
            metadata["parent_container"] = Path(source_path).name
            metadata["embedded_offset"] = start_offset
        else:
            is_embedded = False
            artifact_type = "primary"
            if source_file_ext and source_file_ext not in sig.extensions:
                metadata["extension_mismatch"] = True
                metadata["expected_extension"] = sig.extensions[0]
                metadata["actual_extension"] = source_file_ext

        self._file_counter += 1
        header_hex = sample_data[:len(sig.header)].hex().upper()
        trailer_hex = ""
        if sig.trailer and sample_data[-len(sig.trailer):] == sig.trailer:
            trailer_hex = sig.trailer.hex().upper()

        recovery_status = "COMPLETE" if sig.trailer and trailer_hex else "PARTIAL"

        cf = CarvedFile(
            id=self._file_counter,
            signature=sig,
            start_offset=start_offset,
            end_offset=end_offset,
            size=size,
            confidence=round(conf, 4),
            header_hex=header_hex,
            trailer_hex=trailer_hex,
            recovery_status=recovery_status,
            validation=validation,
            hashes=hashes,
            entropy=entropy,
            metadata=metadata,
            blocks=[(start_offset, end_offset)],
            data=full_data if size <= 10 * 1024 * 1024 else None,
            is_embedded=is_embedded,
            artifact_type=artifact_type,
        )

        self._registry.register(start_offset, conf, self._file_counter, source_path)
        logger.info(f"Carved [{cf.type_name}] at offset 0x{start_offset:X} ({cf.size:,} bytes) in {Path(source_path).name}")
        return cf


    def _find_end(
        self,
        start: int,
        sig: FileSignature,
        reader: SourceReader,
    ) -> int:
        return find_file_end(start, sig, reader, block_size=BLOCK_SIZE, read_ahead=READ_AHEAD)


    @property
    def _custody(self) -> List[CustodyEntry]:
        return self.custody.entries

    def _log(self, message: str, source_hash: str = ""):
        self.custody.log(message, source_hash=source_hash)

    def _extract_metadata(self, data: bytes, sig: FileSignature) -> Dict:
        return extract_basic_metadata(data, getattr(sig, "validator", ""))

    @staticmethod
    def _detect_type(path: str) -> str:
        return detect_source_type(path)