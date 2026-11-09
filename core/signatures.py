from __future__ import annotations
import sqlite3
from pathlib import Path
from collections import defaultdict
from typing import List, Optional, Dict
from .models import FileSignature



_BUILTIN: List[FileSignature] = [
    FileSignature(
        id="png", name="PNG Image", description="Portable Network Graphics",
        category="image", extensions=["png"], mime_type="image/png",
        header=bytes.fromhex("89504E470D0A1A0A"),
        trailer=bytes.fromhex("49454E44AE426082"),
        max_file_size=50*1024*1024, validator="validate_png", confidence=0.95,
    ),
    FileSignature(
        id="jpeg", name="JPEG Image", description="JPEG / JFIF image",
        category="image", extensions=["jpg", "jpeg"], mime_type="image/jpeg",
        header=bytes.fromhex("FFD8FF"),
        trailer=bytes.fromhex("FFD9"),
        max_file_size=30*1024*1024, validator="validate_jpeg", confidence=0.90,
    ),
    FileSignature(
        id="gif87", name="GIF Image (87a)", description="Graphics Interchange Format 87a",
        category="image", extensions=["gif"], mime_type="image/gif",
        header=b"GIF87a", trailer=b"\x3B",
        max_file_size=20*1024*1024, validator="validate_generic", confidence=0.90,
    ),
    FileSignature(
        id="gif89", name="GIF Image (89a)", description="Graphics Interchange Format 89a",
        category="image", extensions=["gif"], mime_type="image/gif",
        header=b"GIF89a", trailer=b"\x3B",
        max_file_size=20*1024*1024, validator="validate_generic", confidence=0.90,
    ),
    FileSignature(
        id="bmp", name="BMP Image", description="Windows Bitmap",
        category="image", extensions=["bmp"], mime_type="image/bmp",
        header=b"BM",
        max_file_size=50*1024*1024, validator="validate_bmp", confidence=0.75,
    ),
    FileSignature(
        id="webp", name="WebP Image", description="WebP image",
        category="image", extensions=["webp"], mime_type="image/webp",
        header=b"RIFF",   # checked further in validator
        max_file_size=30*1024*1024, validator="validate_webp", confidence=0.80,
    ),
    FileSignature(
        id="tiff_le", name="TIFF Image (LE)", description="Tagged Image File Format — little-endian",
        category="image", extensions=["tif", "tiff"], mime_type="image/tiff",
        header=bytes.fromhex("49492A00"),
        max_file_size=200*1024*1024, validator="validate_generic", confidence=0.85,
    ),
    FileSignature(
        id="tiff_be", name="TIFF Image (BE)", description="Tagged Image File Format — big-endian",
        category="image", extensions=["tif", "tiff"], mime_type="image/tiff",
        header=bytes.fromhex("4D4D002A"),
        max_file_size=200*1024*1024, validator="validate_generic", confidence=0.85,
    ),

    FileSignature(
        id="pdf", name="PDF Document", description="Adobe Portable Document Format",
        category="document", extensions=["pdf"], mime_type="application/pdf",
        header=b"%PDF-",
        trailer=b"%%EOF",
        max_file_size=200*1024*1024, validator="validate_pdf", confidence=0.92,
    ),
    FileSignature(
        id="docx", name="Word Document", description="Microsoft Word OOXML",
        category="document", extensions=["docx"],
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        header=bytes.fromhex("504B0304"),
        trailer=bytes.fromhex("504B0506"),
        max_file_size=50*1024*1024, validator="validate_docx", confidence=0.82,
        zip_inner_paths=["word/document.xml", "[Content_Types].xml"],
    ),
    FileSignature(
        id="xlsx", name="Excel Spreadsheet", description="Microsoft Excel OOXML",
        category="document", extensions=["xlsx"],
        mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        header=bytes.fromhex("504B0304"),
        trailer=bytes.fromhex("504B0506"),
        max_file_size=50*1024*1024, validator="validate_xlsx", confidence=0.82,
        zip_inner_paths=["xl/workbook.xml"],
    ),
    FileSignature(
        id="pptx", name="PowerPoint Presentation", description="Microsoft PowerPoint OOXML",
        category="document", extensions=["pptx"],
        mime_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        header=bytes.fromhex("504B0304"),
        trailer=bytes.fromhex("504B0506"),
        max_file_size=100*1024*1024, validator="validate_pptx", confidence=0.82,
        zip_inner_paths=["ppt/presentation.xml"],
    ),
    FileSignature(
        id="doc_ole", name="Word Document (OLE)", description="Microsoft Word 97-2003",
        category="document", extensions=["doc"],
        mime_type="application/msword",
        header=bytes.fromhex("D0CF11E0A1B11AE1"),
        max_file_size=50*1024*1024, validator="validate_ole", confidence=0.88,
    ),
    FileSignature(
        id="xls_ole", name="Excel (OLE)", description="Microsoft Excel 97-2003",
        category="document", extensions=["xls"],
        mime_type="application/vnd.ms-excel",
        header=bytes.fromhex("D0CF11E0A1B11AE1"),
        max_file_size=50*1024*1024, validator="validate_ole", confidence=0.82,
    ),
    FileSignature(
        id="rtf", name="RTF Document", description="Rich Text Format",
        category="document", extensions=["rtf"], mime_type="application/rtf",
        header=b"{\\rtf",
        max_file_size=30*1024*1024, validator="validate_generic", confidence=0.90,
    ),

    FileSignature(
        id="zip", name="ZIP Archive", description="ZIP compressed archive",
        category="archive", extensions=["zip"], mime_type="application/zip",
        header=bytes.fromhex("504B0304"),
        trailer=bytes.fromhex("504B0506"),
        max_file_size=500*1024*1024, validator="validate_zip", confidence=0.72,
    ),
    FileSignature(
        id="rar4", name="RAR Archive (v4)", description="RAR compressed archive v1.5-4.x",
        category="archive", extensions=["rar"], mime_type="application/x-rar-compressed",
        header=bytes.fromhex("526172211A0700"),
        max_file_size=500*1024*1024, validator="validate_generic", confidence=0.92,
    ),
    FileSignature(
        id="rar5", name="RAR Archive (v5)", description="RAR compressed archive v5+",
        category="archive", extensions=["rar"], mime_type="application/x-rar-compressed",
        header=bytes.fromhex("526172211A070100"),
        max_file_size=500*1024*1024, validator="validate_generic", confidence=0.95,
    ),
    FileSignature(
        id="7z", name="7-Zip Archive", description="7-Zip compressed archive",
        category="archive", extensions=["7z"], mime_type="application/x-7z-compressed",
        header=bytes.fromhex("377ABCAF271C"),
        max_file_size=500*1024*1024, validator="validate_generic", confidence=0.95,
    ),
    FileSignature(
        id="gz", name="GZIP Archive", description="GNU Zip compressed data",
        category="archive", extensions=["gz"], mime_type="application/gzip",
        header=bytes.fromhex("1F8B"),
        max_file_size=200*1024*1024, validator="validate_gz", confidence=0.88,
    ),
    FileSignature(
        id="bz2", name="BZ2 Archive", description="bzip2 compressed data",
        category="archive", extensions=["bz2"], mime_type="application/x-bzip2",
        header=b"BZh",
        max_file_size=200*1024*1024, validator="validate_bz2", confidence=0.90,
    ),
    FileSignature(
        id="tar", name="TAR Archive", description="POSIX tape archive",
        category="archive", extensions=["tar"], mime_type="application/x-tar",
        header=b"ustar", header_offset=257,
        max_file_size=500*1024*1024, validator="validate_generic", confidence=0.85,
    ),

    FileSignature(
        id="mp4", name="MP4 Video", description="MPEG-4 video",
        category="video", extensions=["mp4", "m4v"], mime_type="video/mp4",
        header=b"ftyp", header_offset=4,
        max_file_size=2*1024*1024*1024, validator="validate_mp4", confidence=0.85,
    ),
    FileSignature(
        id="avi", name="AVI Video", description="Audio Video Interleave",
        category="video", extensions=["avi"], mime_type="video/x-msvideo",
        header=b"RIFF",
        max_file_size=2*1024*1024*1024, validator="validate_avi", confidence=0.78,
    ),
    FileSignature(
        id="mkv", name="MKV Video", description="Matroska video",
        category="video", extensions=["mkv"], mime_type="video/x-matroska",
        header=bytes.fromhex("1A45DFA3"),
        max_file_size=2*1024*1024*1024, validator="validate_generic", confidence=0.90,
    ),
    FileSignature(
        id="mov", name="MOV Video", description="Apple QuickTime Movie",
        category="video", extensions=["mov"], mime_type="video/quicktime",
        header=b"ftyp", header_offset=4,
        max_file_size=2*1024*1024*1024, validator="validate_mp4", confidence=0.85,
    ),
    FileSignature(
    id="wmv", name="Windows Media Video", description="ASF/WMV container",
    category="video", extensions=["wmv", "wma", "asf"],
    mime_type="video/x-ms-wmv",
    header=bytes.fromhex("3026B2758E66CF11"),
    max_file_size=4*1024*1024*1024,
    validator="validate_asf",
    confidence=0.92,
),

    FileSignature(
        id="mp3_id3", name="MP3 Audio (ID3)", description="MP3 with ID3 tag",
        category="audio", extensions=["mp3"], mime_type="audio/mpeg",
        header=b"ID3",
        max_file_size=100*1024*1024, validator="validate_id3", confidence=0.90,
    ),
  
    FileSignature(
        id="wav", name="WAV Audio", description="Waveform Audio File Format",
        category="audio", extensions=["wav"], mime_type="audio/wav",
        header=b"RIFF",
        max_file_size=500*1024*1024, validator="validate_wav", confidence=0.78,
    ),
    FileSignature(
        id="flac", name="FLAC Audio", description="Free Lossless Audio Codec",
        category="audio", extensions=["flac"], mime_type="audio/flac",
        header=b"fLaC",
        max_file_size=500*1024*1024, validator="validate_generic", confidence=0.95,
    ),
    FileSignature(
        id="ogg", name="OGG Audio", description="Ogg Vorbis audio",
        category="audio", extensions=["ogg"], mime_type="audio/ogg",
        header=b"OggS",
        max_file_size=100*1024*1024, validator="validate_generic", confidence=0.95,
    ),
    FileSignature(
        id="aac", name="AAC Audio", description="Advanced Audio Coding",
        category="audio", extensions=["aac"], mime_type="audio/aac",
        header=bytes.fromhex("FFF1"),
        max_file_size=100*1024*1024, validator="validate_aac", confidence=0.75,
    ),

    FileSignature(
        id="exe_pe", name="Windows Executable", description="Windows PE executable (EXE/DLL)",
        category="executable", extensions=["exe", "dll", "sys"],
        mime_type="application/x-msdownload",
        header=b"MZ",
        max_file_size=200*1024*1024, validator="validate_pe", confidence=0.70,
    ),
    FileSignature(
        id="elf", name="ELF Binary", description="Linux/Unix ELF executable",
        category="executable", extensions=["elf", "so"],
        mime_type="application/x-elf",
        header=bytes.fromhex("7F454C46"),
        max_file_size=200*1024*1024, validator="validate_elf", confidence=0.92,
    ),
    FileSignature(
        id="macho", name="Mach-O Binary", description="macOS Mach-O executable",
        category="executable", extensions=["macho"],
        mime_type="application/x-mach-binary",
        header=bytes.fromhex("CEFAEDFE"),
        max_file_size=200*1024*1024, validator="validate_generic", confidence=0.90,
    ),

    # ── Database ──────────────────────────────
    FileSignature(
        id="sqlite", name="SQLite Database", description="SQLite3 database file",
        category="database", extensions=["db", "sqlite", "sqlite3"],
        mime_type="application/x-sqlite3",
        header=b"SQLite format 3\x00",
        max_file_size=2*1024*1024*1024, validator="validate_generic", confidence=0.98,
    ),

    FileSignature(
        id="pst", name="Outlook PST", description="Microsoft Outlook Personal Storage Table",
        category="email", extensions=["pst"],
        mime_type="application/vnd.ms-outlook",
        header=bytes.fromhex("2142444E"),
        max_file_size=2*1024*1024*1024, validator="validate_generic", confidence=0.95,
    ),
    FileSignature(
        id="eml", name="Email Message", description="RFC 822 email message",
        category="email", extensions=["eml"], mime_type="message/rfc822",
        header=b"From ",
        max_file_size=10*1024*1024, validator="validate_eml", confidence=0.85,
    ),

    FileSignature(
        id="vmdk", name="VMDK Disk Image", description="VMware Virtual Disk",
        category="disk_image", extensions=["vmdk"],
        mime_type="application/x-vmdk",
        header=b"KDMV",
        max_file_size=2*1024*1024*1024, validator="validate_generic", confidence=0.95,
    ),
    FileSignature(
        id="vhd", name="VHD Disk Image", description="Virtual Hard Disk",
        category="disk_image", extensions=["vhd"],
        mime_type="application/x-vhd",
        header=b"conectix",
        max_file_size=2*1024*1024*1024, validator="validate_generic", confidence=0.92,
    ),
]



_ZIP_FAMILY: List[FileSignature] = [
    s for s in _BUILTIN if s.id in ("docx", "xlsx", "pptx")
]
_ZIP_BASE: FileSignature = next(s for s in _BUILTIN if s.id == "zip")

_RIFF_FAMILY: List[FileSignature] = [
    s for s in _BUILTIN if s.id in ("avi", "wav", "webp")
]

def resolve_zip_subtype(data: bytes) -> FileSignature:
    """Given raw ZIP bytes, return the most specific FileSignature."""
    for sig in _ZIP_FAMILY:
        for inner in sig.zip_inner_paths:
            if inner.encode() in data[:4096]:
                return sig
    return _ZIP_BASE

def resolve_riff_subtype(data: bytes) -> FileSignature:
    """RIFF container — peek bytes 8-12 to identify WAV / AVI / WebP."""
    if len(data) >= 12:
        tag = data[8:12]
        if tag == b"WAVE":
            return next(s for s in _RIFF_FAMILY if s.id == "wav")
        if tag == b"AVI ":
            return next(s for s in _RIFF_FAMILY if s.id == "avi")
        if tag == b"WEBP":
            return next(s for s in _RIFF_FAMILY if s.id == "webp")
    return next(s for s in _BUILTIN if s.id == "avi")  # fallback



class SignatureDatabase:
    """
    Manages file signatures in memory + SQLite.
    Deduplication: ZIP-family and RIFF-family are collapsed to the
    most specific match at lookup time, not stored as multiple entries.
    """

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._sigs: Dict[str, FileSignature] = {}
        self._zero_offset_by_first_byte: Dict[int, List[FileSignature]] = defaultdict(list)
        self._offset_sigs: List[FileSignature] = []
        self._init_db()
        self._load_builtins()
        if db_path != ":memory:":
            self._load_from_db()
        self._rebuild_index()

    def _rebuild_index(self):
        """Build fast byte index for zero-offset headers."""
        self._zero_offset_by_first_byte = defaultdict(list)
        self._offset_sigs = []
        for sig in self._sigs.values():
            if sig.id in ("zip", "avi", "wav", "webp"):
                continue
            if sig.header_offset == 0 and len(sig.header) > 0:
                self._zero_offset_by_first_byte[sig.header[0]].append(sig)
            else:
                self._offset_sigs.append(sig)


    def _init_db(self):
        conn = self._conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS custom_signatures (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                category TEXT,
                extensions TEXT,
                mime_type TEXT,
                header_hex TEXT NOT NULL,
                header_offset INTEGER DEFAULT 0,
                trailer_hex TEXT,
                max_file_size INTEGER,
                validator TEXT,
                confidence REAL,
                zip_inner_paths TEXT
            )
        """)
        conn.commit()
        conn.close()

    def _load_builtins(self):
        for sig in _BUILTIN:
            self._sigs[sig.id] = sig

    def _load_from_db(self):
        conn = self._conn()
        rows = conn.execute("SELECT * FROM custom_signatures").fetchall()
        conn.close()
        for row in rows:
            sig = self._row_to_sig(row)
            self._sigs[sig.id] = sig

    # ── Public API ───────────────────────────

    @property
    def all(self) -> List[FileSignature]:
        return list(self._sigs.values())

    def get(self, sig_id: str) -> Optional[FileSignature]:
        return self._sigs.get(sig_id)

    def add_custom(self, sig: FileSignature):
        self._sigs[sig.id] = sig
        self._rebuild_index()
        if self.db_path != ":memory:":
            conn = self._conn()
            conn.execute(
                """INSERT OR REPLACE INTO custom_signatures VALUES
                   (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    sig.id, sig.name, sig.description, sig.category,
                    ",".join(sig.extensions), sig.mime_type,
                    sig.header.hex(), sig.header_offset,
                    sig.trailer.hex() if sig.trailer else None,
                    sig.max_file_size, sig.validator, sig.confidence,
                    ",".join(sig.zip_inner_paths),
                ),
            )
            conn.commit()
            conn.close()

    def remove(self, sig_id: str):
        self._sigs.pop(sig_id, None)
        self._rebuild_index()
        if self.db_path != ":memory:":
            conn = self._conn()
            conn.execute("DELETE FROM custom_signatures WHERE id=?", (sig_id,))
            conn.commit()
            conn.close()

    def find_by_header(self, block: bytes, block_offset: int = 0) -> List[FileSignature]:
        """
        Return matching signatures for a given data block, with
        ZIP-family and RIFF-family resolved to the most specific type.
        Uses first-byte indexing for 10x-30x faster carving throughput.
        """
        if block_offset >= len(block):
            return []

        b = block[block_offset]
        matches: List[FileSignature] = []
        seen_ids: set = set()

        candidate_sigs = self._zero_offset_by_first_byte.get(b)
        if candidate_sigs:
            for sig in candidate_sigs:
                hlen = len(sig.header)
                if block_offset + hlen <= len(block):
                    if block[block_offset : block_offset + hlen] == sig.header:
                        if sig.id not in seen_ids:
                            matches.append(sig)
                            seen_ids.add(sig.id)
        if b == 0x50 and block_offset + 4 <= len(block) and block[block_offset : block_offset + 4] == b"PK\x03\x04":
            resolved = resolve_zip_subtype(block[block_offset:])
            if resolved.id not in seen_ids:
                matches.append(resolved)
                seen_ids.add(resolved.id)

        if b == 0x52 and block_offset + 4 <= len(block) and block[block_offset : block_offset + 4] == b"RIFF":
            resolved = resolve_riff_subtype(block[block_offset:])
            if resolved.id not in seen_ids:
                matches.append(resolved)
                seen_ids.add(resolved.id)

        if self._offset_sigs:
            for sig in self._offset_sigs:
                start = block_offset + sig.header_offset
                hlen = len(sig.header)
                if start + hlen <= len(block):
                    if block[start : start + hlen] == sig.header:
                        if sig.id not in seen_ids:
                            matches.append(sig)
                            seen_ids.add(sig.id)

        return matches

    def stats(self) -> Dict[str, int]:
        cats: Dict[str, int] = {}
        for s in self._sigs.values():
            cats[s.category] = cats.get(s.category, 0) + 1
        return cats


    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    @staticmethod
    def _row_to_sig(row) -> FileSignature:
        (sid, name, desc, cat, exts, mime, hx, hoff,
         tx, maxsz, val, conf, zips) = row
        return FileSignature(
            id=sid, name=name, description=desc or "", category=cat or "custom",
            extensions=exts.split(",") if exts else ["bin"],
            mime_type=mime or "application/octet-stream",
            header=bytes.fromhex(hx),
            header_offset=hoff or 0,
            trailer=bytes.fromhex(tx) if tx else None,
            max_file_size=maxsz or 50*1024*1024,
            validator=val or "validate_generic",
            confidence=conf or 0.7,
            zip_inner_paths=zips.split(",") if zips else [],
        )
