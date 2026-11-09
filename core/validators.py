from __future__ import annotations
import logging
import struct
import zlib
from .models import ValidationResult

logger = logging.getLogger(__name__)


def _ok(msg: str, boost: float = 0.0) -> ValidationResult:
    return ValidationResult(True, msg, boost)

def _fail(msg: str) -> ValidationResult:
    return ValidationResult(False, msg, -0.5)


def validate_png(data: bytes) -> ValidationResult:
    if len(data) < 24:
        return _fail("Too small for PNG")
    if data[:8] != bytes.fromhex("89504E470D0A1A0A"):
        return _fail("Invalid PNG header")
    has_footer = data[-8:] == bytes.fromhex("49454E44AE426082")
    if not has_footer:
        return ValidationResult(True, "PNG — missing IEND chunk (truncated)", -0.15)
    # Walk chunks
    pos = 8
    chunk_types = []
    while pos + 12 <= len(data):
        try:
            clen = struct.unpack(">I", data[pos:pos+4])[0]
            ctype = data[pos+4:pos+8]
            chunk_types.append(ctype)
            if ctype == b"IDAT":
                chunk_data = data[pos+8:pos+8+clen]
                try:
                    zlib.decompress(chunk_data, -15)
                    return _ok("Valid PNG — IDAT decompressed OK", 0.05)
                except Exception:
                    pass
            pos += 12 + clen
        except Exception as e:
            logger.debug(f"PNG chunk parsing error at offset {pos}: {e}")
            break
    ihdr_ok = b"IHDR" in chunk_types
    return _ok("Valid PNG structure" if ihdr_ok else "PNG — IHDR missing", 0.0 if ihdr_ok else -0.1)


def validate_jpeg(data: bytes) -> ValidationResult:
    if len(data) < 4:
        return _fail("Too small for JPEG")
    if data[:2] != b"\xFF\xD8":
        return _fail("Invalid JPEG SOI marker")
    has_eoi = data[-2:] == b"\xFF\xD9"
    boost = 0.0
    notes = []
    if b"JFIF" in data[:20]:
        notes.append("JFIF")
        boost += 0.03
    if b"Exif" in data[:20]:
        notes.append("Exif")
        boost += 0.03
    has_sof = any(m in data for m in [b"\xFF\xC0", b"\xFF\xC1", b"\xFF\xC2"])
    has_sos = b"\xFF\xDA" in data
    if not has_sof or not has_sos:
        return ValidationResult(True, "JPEG — missing SOF/SOS segments", -0.2)
    if not has_eoi:
        return ValidationResult(True, f"JPEG ({','.join(notes) or 'plain'}) — truncated (no EOI)", -0.1)
    label = f"Valid JPEG ({','.join(notes)})" if notes else "Valid JPEG"
    return _ok(label, boost)



def validate_pdf(data: bytes) -> ValidationResult:
    if not data[:5] == b"%PDF-":
        return _fail("Not a PDF — missing %PDF- header")
    version = data[5:8].decode("ascii", errors="replace")
    has_eof = b"%%EOF" in data[-256:]
    has_xref = b"xref" in data or b"startxref" in data
    boost = 0.0
    if has_xref:
        boost += 0.05
    if not has_eof:
        return ValidationResult(True, f"PDF v{version} — no %%EOF (truncated)", boost - 0.1)
    return _ok(f"Valid PDF v{version}", boost)




def validate_zip(data: bytes) -> ValidationResult:
    if data[:4] != bytes.fromhex("504B0304"):
        return _fail("Not a ZIP archive")
    # Check EOCD signature in last 64KB
    eocd_sig = bytes.fromhex("504B0506")
    search_area = data[-min(65536, len(data)):]
    has_eocd = eocd_sig in search_area
    if not has_eocd:
        return ValidationResult(True, "ZIP — EOCD record not found (truncated or split)", -0.2)
    return _ok("Valid ZIP archive", 0.05)


def validate_docx(data: bytes) -> ValidationResult:
    r = validate_zip(data)
    if not r.is_valid:
        return r
    markers = [b"word/document.xml", b"[Content_Types].xml", b"word/_rels/"]
    found = sum(1 for m in markers if m in data[:8192])
    if found == 0:
        return ValidationResult(True, "ZIP — no DOCX internal markers", -0.1)
    return _ok(f"Valid DOCX ({found}/3 markers)", 0.08)


def validate_xlsx(data: bytes) -> ValidationResult:
    r = validate_zip(data)
    if not r.is_valid:
        return r
    if b"xl/workbook.xml" not in data[:8192]:
        return ValidationResult(True, "ZIP — no xl/workbook.xml", -0.1)
    return _ok("Valid XLSX", 0.08)


def validate_pptx(data: bytes) -> ValidationResult:
    r = validate_zip(data)
    if not r.is_valid:
        return r
    if b"ppt/presentation.xml" not in data[:8192]:
        return ValidationResult(True, "ZIP — no ppt/presentation.xml", -0.1)
    return _ok("Valid PPTX", 0.08)



def validate_ole(data: bytes) -> ValidationResult:
    if data[:8] != bytes.fromhex("D0CF11E0A1B11AE1"):
        return _fail("Not an OLE2 document")
    return _ok("Valid OLE2 compound document", 0.03)


def validate_pe(data: bytes) -> ValidationResult:
    if len(data) < 64 or data[:2] != b"MZ":
        return _fail("Not a PE — missing MZ signature")
    try:
        pe_offset = struct.unpack_from("<I", data, 60)[0]
        if pe_offset < 64 or pe_offset + 24 > len(data):
            return _fail("MZ stub — invalid PE offset")
        if data[pe_offset : pe_offset + 4] == b"PE\x00\x00":
            machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
            arch = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64"}.get(machine)
            if not arch:
                return _fail(f"Unrecognized PE machine type (0x{machine:04X})")
            return _ok(f"Valid PE executable ({arch})", 0.10)
        return _fail("MZ present — PE signature not found")
    except Exception as e:
        logger.debug(f"PE parsing error: {e}")
        return _fail(f"PE parse error: {e}")



def validate_elf(data: bytes) -> ValidationResult:
    if len(data) < 16 or data[:4] != b"\x7fELF":
        return _fail("Not an ELF binary")
    ei_class = data[4]
    ei_data = data[5]
    bits = {1: "32-bit", 2: "64-bit"}.get(ei_class, "unknown")
    endian = {1: "LE", 2: "BE"}.get(ei_data, "?")
    return _ok(f"Valid ELF binary ({bits} {endian})", 0.05)


def validate_bmp(data: bytes) -> ValidationResult:
    if len(data) < 54 or data[:2] != b"BM":
        return _fail("Not a BMP file")
    try:
        file_size = struct.unpack_from("<I", data, 2)[0]
        pixel_offset = struct.unpack_from("<I", data, 10)[0]
        header_size = struct.unpack_from("<I", data, 14)[0]
        width = struct.unpack_from("<i", data, 18)[0]
        height = struct.unpack_from("<i", data, 22)[0]
        planes = struct.unpack_from("<H", data, 26)[0]
        bpp = struct.unpack_from("<H", data, 28)[0]

        if header_size not in (12, 40, 52, 56, 64, 108, 124):
            return _fail(f"Invalid BMP header size ({header_size})")
        if planes != 1:
            return _fail(f"Invalid BMP planes ({planes})")
        if bpp not in (1, 4, 8, 16, 24, 32):
            return _fail(f"Invalid BMP bits per pixel ({bpp})")
        if pixel_offset < 14 + header_size or pixel_offset > 65536:
            return _fail(f"Invalid BMP pixel offset ({pixel_offset})")
        w, h = abs(width), abs(height)
        if w == 0 or h == 0 or w > 32768 or h > 32768:
            return _fail(f"Invalid BMP dimensions ({w}x{h})")
        return _ok(f"Valid BMP {w}x{h}px ({file_size:,} B)", 0.05)
    except Exception as e:
        logger.debug(f"BMP header parsing error: {e}")
        return _fail(f"BMP parse error: {e}")



def validate_wav(data: bytes) -> ValidationResult:
    if len(data) < 12:
        return _fail("Too small for WAV")
    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return _fail("Not a WAV — missing RIFF/WAVE signature")
    return _ok("Valid WAV audio", 0.05)

def validate_avi(data: bytes) -> ValidationResult:
    if len(data) < 12:
        return _fail("Too small for AVI")
    if data[:4] != b"RIFF" or data[8:12] != b"AVI ":
        return _fail("Not an AVI — missing RIFF/AVI signature")
    return _ok("Valid AVI video", 0.05)



def validate_webp(data: bytes) -> ValidationResult:
    if len(data) < 12:
        return _fail("Too small for WebP")
    if data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return _fail("Not a WebP — missing RIFF/WEBP signature")
    return _ok("Valid WebP image", 0.05)


def validate_mp4(data: bytes) -> ValidationResult:
    if len(data) < 12:
        return _fail("Too small for MP4")
    # ftyp box is at offset 4
    if data[4:8] != b"ftyp":
        return ValidationResult(True, "MP4 — ftyp box not at offset 4", -0.15)
    brand = data[8:12].decode("ascii", errors="replace").strip()
    return _ok(f"Valid MP4 (brand: {brand!r})", 0.05)


def validate_gz(data: bytes) -> ValidationResult:
    if len(data) < 10 or data[:2] != bytes.fromhex("1F8B"):
        return _fail("Not a GZIP file")
    cm = data[2]
    flg = data[3]
    if cm != 8:
        return _fail(f"GZIP invalid compression method ({cm})")
    if flg & 0xE0 != 0:
        return _fail(f"GZIP invalid flags ({flg:#x})")
    try:
        import zlib
        dc = zlib.decompressobj(-zlib.MAX_WBITS)
        chunk = data[10 : min(len(data), 512)]
        out = dc.decompress(chunk)
        if len(out) == 0 and not dc.unused_data:
            return _fail("GZIP decompress returned empty")
        return _ok("Valid GZIP archive", 0.05)
    except Exception as e:
        return _fail(f"GZIP stream error: {e}")



def validate_bz2(data: bytes) -> ValidationResult:
    """Validate bzip2 compressed archive header and stream structure."""
    if len(data) < 10:
        return _fail("Too small for BZ2 archive")
    if data[:3] != b"BZh":
        return _fail("Not a BZ2 file — missing BZh magic")
    # Block size digit '1' through '9'
    block_size_digit = data[3:4]
    if block_size_digit not in b"123456789":
        return _fail(f"Invalid BZ2 block size level ({block_size_digit})")
    
    has_block_magic = (
        data[4:10] == bytes.fromhex("314159265359")
        or data[4:10] == bytes.fromhex("177245385090")
    )
    if not has_block_magic:
        try:
            import bz2
            decompressor = bz2.BZ2Decompressor()
            decompressor.decompress(data[: min(len(data), 4096)])
        except Exception:
            return _fail("Invalid BZ2 block header magic (likely false positive)")

    level = int(chr(data[3]))
    return _ok(f"Valid BZ2 archive (level {level}, block size {level * 100} KB)", 0.05)



def validate_eml(data: bytes) -> ValidationResult:
    """Validate RFC 822 / MIME email message headers strictly to reject false positives."""
    if len(data) < 30:
        return _fail("Too small for email message")
    
    sample = data[: min(len(data), 8192)]
    try:
        text = sample.decode("utf-8", errors="replace")
    except Exception:
        return _fail("Non-textual data in email header")

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return _fail("Empty email message")

    EMAIL_HEADERS = (
        "from:", "to:", "subject:", "date:", "message-id:",
        "mime-version:", "content-type:", "received:", "reply-to:",
        "delivered-to:", "return-path:", "cc:", "bcc:", "x-mailer:"
    )

    found_headers = set()
    for line in lines[:35]:
        line_lower = line.lower()
        for h in EMAIL_HEADERS:
            if line_lower.startswith(h):
                found_headers.add(h)
                break

    if text.startswith("From "):
        found_headers.add("from (mbox)")

    if len(found_headers) < 2:
        return _fail(f"Insufficient email headers ({len(found_headers)}: {list(found_headers)}) — false positive")

    return _ok(f"Valid RFC 822 email message ({len(found_headers)} headers identified)", 0.05)



def validate_mp3_sync(data: bytes) -> ValidationResult:
    """Strict MPEG audio frame validator — requires 2+ consecutive valid frames."""
    if len(data) < 8:
        return _fail("Too short for MP3")

    def parse_frame(buf: bytes, pos: int):
        """Return frame_length if buf[pos:pos+4] is a valid MPEG audio header, else 0."""
        if pos + 4 > len(buf):
            return 0
        b0, b1, b2, b3 = buf[pos], buf[pos+1], buf[pos+2], buf[pos+3]
        if b0 != 0xFF or (b1 & 0xE0) != 0xE0:
            return 0
        version = (b1 >> 3) & 0x03    
        layer   = (b1 >> 1) & 0x03    
        if version == 1 or layer == 0:
            return 0
        bitrate_idx = (b2 >> 4) & 0x0F
        sr_idx      = (b2 >> 2) & 0x03
        padding     = (b2 >> 1) & 0x01
        if bitrate_idx in (0, 0x0F) or sr_idx == 0x03:
            return 0
        BR_V1_L3 = [0,32,40,48,56,64,80,96,112,128,160,192,224,256,320,0]
        BR_V1_L2 = [0,32,48,56,64,80,96,112,128,160,192,224,256,320,384,0]
        BR_V1_L1 = [0,32,64,96,128,160,192,224,256,288,320,352,384,416,448,0]
        BR_V2_L1 = [0,32,48,56,64,80,96,112,128,144,160,176,192,224,256,0]
        BR_V2_L23= [0,8,16,24,32,40,48,56,64,80,96,112,128,144,160,0]
        if version == 3:
            table = BR_V1_L1 if layer == 3 else (BR_V1_L2 if layer == 2 else BR_V1_L3)
        else:
            table = BR_V2_L1 if layer == 3 else BR_V2_L23
        bitrate = table[bitrate_idx] * 1000
        SR = [44100, 48000, 32000, 0]
        sr = SR[sr_idx]
        if version == 2:   # MPEG2
            sr //= 2
        elif version == 0: # MPEG2.5
            sr //= 4
        if sr == 0 or bitrate == 0:
            return 0
        if layer == 3:      # Layer I
            frame_len = (12 * bitrate // sr + padding) * 4
        elif layer == 1:    # Layer III
            frame_len = 144 * bitrate // sr + padding
            if version != 3:  # MPEG2/2.5 Layer III
                frame_len = 72 * bitrate // sr + padding
        else:               # Layer II
            frame_len = 144 * bitrate // sr + padding
        if frame_len < 24 or frame_len > 2881:
            return 0
        return frame_len

    flen0 = parse_frame(data, 0)
    if flen0 == 0:
        return _fail("Not a valid MPEG audio frame at offset 0")

    if len(data) >= flen0 + 4:
        flen1 = parse_frame(data, flen0)
        if flen1 == 0:
            return _fail("MP3 second consecutive frame invalid (likely false positive)")
        if len(data) >= flen0 + flen1 + 4:
            flen2 = parse_frame(data, flen0 + flen1)
            if flen2 == 0:
                return ValidationResult(True, "MP3 — 2 frames OK, 3rd failed", -0.05)
    else:
        return ValidationResult(True, "MP3 — single frame only (weak)", -0.20)

    return _ok("Valid MP3 — consecutive frames confirmed", 0.05)


def validate_aac(data: bytes) -> ValidationResult:
    if len(data) < 7:
        return _fail("Too short for AAC ADTS")
    if data[0] != 0xFF or (data[1] & 0xF6) != 0xF0:
        return _fail("Invalid AAC ADTS sync")
    sr_idx = (data[2] >> 2) & 0x0F
    if sr_idx >= 13:
        return _fail("Reserved AAC sampling rate")
    frame_len = ((data[3] & 0x03) << 11) | (data[4] << 3) | ((data[5] & 0xE0) >> 5)
    if frame_len < 7 or frame_len > 8192:
        return _fail(f"Invalid AAC frame length ({frame_len})")
    if len(data) >= frame_len + 2:
        if data[frame_len] != 0xFF or (data[frame_len + 1] & 0xF6) != 0xF0:
            return _fail("AAC consecutive frame sync failed")
    return _ok("Valid AAC ADTS stream", 0.05)


def validate_id3(data: bytes) -> ValidationResult:
    """Validate ID3v2 container header (ID3v2.2, ID3v2.3, ID3v2.4)."""
    if len(data) < 10:
        return _fail("Too short for ID3 header")
    if data[:3] != b"ID3":
        return _fail("Missing ID3 magic")
    ver = data[3]
    if ver not in (2, 3, 4):
        return _fail(f"Unsupported/invalid ID3 major version 2.{ver}")
    rev = data[4]
    if rev == 0xFF:
        return _fail("Invalid ID3 revision 0xFF")
    flags = data[5]
    if (flags & 0x0F) != 0:
        return _fail("Invalid ID3 flags (reserved lower 4 bits set)")
    # Check synchsafe integer on bytes 6..9 (bit 7 must be 0 for each)
    if any(b & 0x80 for b in data[6:10]):
        return _fail("Invalid ID3 synchsafe size format")
    tag_size = (
        ((data[6] & 0x7F) << 21)
        | ((data[7] & 0x7F) << 14)
        | ((data[8] & 0x7F) << 7)
        | (data[9] & 0x7F)
    )
    if tag_size < 1:
        return _fail(f"Invalid ID3 tag size ({tag_size})")
    if tag_size > 50 * 1024 * 1024:
        return _fail(f"Unreasonable ID3 tag size ({tag_size})")
    # Verify first frame if data allows
    if len(data) >= 14:
        first_frame = data[10:14]
        if first_frame != b"\x00\x00\x00\x00":
            chars = first_frame if ver >= 3 else first_frame[:3]
            if not all((0x41 <= b <= 0x5A) or (0x30 <= b <= 0x39) for b in chars):
                return _fail("Invalid ID3 first frame identifier")
    return _ok(f"Valid ID3v2.{ver} tag (size={tag_size})", 0.05)

def validate_asf(data: bytes) -> ValidationResult:
    """Validate ASF/WMV/WMA container header (16-byte GUID)."""
    ASF_GUID = bytes.fromhex("3026B2758E66CF11A6D900AA0062CE6C")
    if len(data) < 30:
        return _fail("Too small for ASF container")
    if data[:16] != ASF_GUID:
        return _fail("Not an ASF container — invalid GUID")
    try:
        obj_size = struct.unpack_from("<Q", data, 16)[0]
        if obj_size < 30 or obj_size > 0xFFFFFFFF:
            return _fail(f"Invalid ASF header object size ({obj_size})")
        return _ok(f"Valid ASF/WMV container ({obj_size:,} B header)", 0.05)
    except Exception as e:
        return _fail(f"ASF parse error: {e}")


def validate_generic(data: bytes) -> ValidationResult:
    return ValidationResult(True, "Basic header match (no deep validator)", 0.0)



_DISPATCH = {
    "validate_png": validate_png,
    "validate_jpeg": validate_jpeg,
    "validate_pdf": validate_pdf,
    "validate_zip": validate_zip,
    "validate_docx": validate_docx,
    "validate_xlsx": validate_xlsx,
    "validate_pptx": validate_pptx,
    "validate_ole": validate_ole,
    "validate_pe": validate_pe,
    "validate_elf": validate_elf,
    "validate_bmp": validate_bmp,
    "validate_wav": validate_wav,
    "validate_avi": validate_avi,
    "validate_webp": validate_webp,
    "validate_mp4": validate_mp4,
    "validate_gz": validate_gz,
    "validate_mp3_sync": validate_mp3_sync,
    "validate_aac": validate_aac,
    "validate_id3": validate_id3,
    "validate_asf": validate_asf,
    "validate_bz2": validate_bz2,
    "validate_eml": validate_eml,
    "validate_generic": validate_generic,

}


def register_validator(name: str, fn):
    """Register validator at runtime (used by plugins)."""
    if not name or not callable(fn):
        raise ValueError("validator name and callable function are required")
    _DISPATCH[name] = fn


def dispatch(validator_name: str, data: bytes) -> ValidationResult:
    fn = _DISPATCH.get(validator_name, validate_generic)
    try:
        return fn(data)
    except Exception as e:
        logger.warning(f"Validator '{validator_name}' failed: {e}")
        return ValidationResult(True, f"Validator error: {e}", -0.1)
