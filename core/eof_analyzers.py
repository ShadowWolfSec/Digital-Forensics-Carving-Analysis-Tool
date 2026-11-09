from __future__ import annotations

import struct
from typing import Optional

from .models import FileSignature
from .source_reader import SourceReader


def search_trailer(
    start: int,
    sig: FileSignature,
    reader: SourceReader,
    block_size: int = 4096,
    read_ahead: int = 64,
) -> int:
    trailer = sig.trailer
    if not trailer:
        return 0
    t_len = len(trailer)
    chunk_size = block_size * read_ahead  
    max_read = sig.max_file_size

    pos = start
    bytes_read = 0
    while bytes_read < max_read:
        chunk = reader.read_at(pos, chunk_size)
        if not chunk:
            break
        idx = chunk.find(trailer)
        if idx != -1:
            return pos + idx + t_len
        pos += len(chunk) - t_len
        bytes_read += len(chunk)
    return 0


def find_pe_end(
    start: int,
    sig: FileSignature,
    reader: SourceReader,
) -> int:
    try:
        hdr = reader.read_at(start, 512)
        if len(hdr) < 64:
            return 0
        pe_off = struct.unpack_from("<I", hdr, 60)[0]
        if pe_off + 248 > len(hdr):
            return 0
        if hdr[pe_off:pe_off+4] != b"PE\x00\x00":
            return 0
        num_sections = struct.unpack_from("<H", hdr, pe_off + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", hdr, pe_off + 20)[0]
        section_table_offset = pe_off + 24 + opt_hdr_size
        if section_table_offset + num_sections * 40 > len(hdr):
            hdr = reader.read_at(start, section_table_offset + num_sections * 40 + 64)
        max_end = start
        for i in range(num_sections):
            off = section_table_offset + i * 40
            raw_size = struct.unpack_from("<I", hdr, off + 16)[0]
            raw_ptr = struct.unpack_from("<I", hdr, off + 20)[0]
            section_end = start + raw_ptr + raw_size
            if section_end > max_end:
                max_end = section_end
        if max_end > start + 512:
            return max_end
    except Exception:
        pass
    return 0


def find_bmp_end(
    start: int,
    sig: FileSignature,
    reader: SourceReader,
    max_available: int,
) -> int:
    hdr = reader.read_at(start, 6)
    if len(hdr) >= 6:
        bmp_size = struct.unpack_from("<I", hdr, 2)[0]
        if 64 < bmp_size <= min(sig.max_file_size, max_available):
            return start + bmp_size
    return 0


def find_mp4_end(
    start: int,
    sig: FileSignature,
    reader: SourceReader,
    max_available: int,
) -> int:
 
    KNOWN_BOXES = {
        b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide",
        b"uuid", b"meta", b"moof", b"mvex", b"udta", b"styp",
        b"sidx", b"prft", b"pdin",
    }

    max_read = min(sig.max_file_size, max_available)
    curr = start
    mp4_end = start
    box_count = 0
    has_essential_box = False

    while curr < start + max_read:
        hdr = reader.read_at(curr, 16)
        if len(hdr) < 8:
            break

        box_size = struct.unpack_from(">I", hdr, 0)[0]
        box_type = hdr[4:8]

        # Valid box types must be printable 4-character codes or known box types
        is_printable_type = all(32 <= b <= 126 for b in box_type)
        if not (is_printable_type or box_type in KNOWN_BOXES):
            break

        if box_type in (b"ftyp", b"moov", b"mdat", b"moof"):
            has_essential_box = True

        if box_size == 1:
            if len(hdr) < 16:
                break
            box_size = struct.unpack_from(">Q", hdr, 8)[0]
        elif box_size == 0:
            if has_essential_box:
                mp4_end = start + max_available
            break

        if box_size < 8 or box_size > sig.max_file_size:
            break

        curr += box_size
        mp4_end = curr
        box_count += 1

        if curr >= start + max_read:
            break

    if box_count >= 1 and has_essential_box and mp4_end > start:
        return mp4_end

    return 0


def find_file_end(
    start: int,
    sig: FileSignature,
    reader: SourceReader,
    block_size: int = 4096,
    read_ahead: int = 64,
) -> int:
    """
    Find the end offset of a file. Returns start if unable to determine.
    Strategy:
      1. Trailer search (chunked, up to max_file_size)
      2. Format-specific structure analysis (BMP, PE, MP4/MOV, etc.)
      3. Conservative fallback = min(max_file_size, 10MB, remaining_available)
    """
    if sig.trailer:
        end = search_trailer(start, sig, reader, block_size=block_size, read_ahead=read_ahead)
        if end > start:
            return end

    max_available = (reader.size - start) if reader.size and reader.size > start else sig.max_file_size

    if sig.validator == "validate_bmp":
        bmp_end = find_bmp_end(start, sig, reader, max_available)
        if bmp_end > start:
            return bmp_end

    if sig.validator in ("validate_pe",):
        pe_end = find_pe_end(start, sig, reader)
        if pe_end > start:
            return min(pe_end, start + max_available)

    if sig.validator == "validate_mp4" or sig.id in ("mp4", "mov", "m4v"):
        mp4_end = find_mp4_end(start, sig, reader, max_available)
        if mp4_end > start:
            return min(mp4_end, start + max_available)

    return start + min(sig.max_file_size, 10 * 1024 * 1024, max_available)

