from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("core.mft_parser")

MFT_RECORD_MAGIC = b"FILE"
BAAD_RECORD_MAGIC = b"BAAD"
MFT_RECORD_SIZE = 1024

ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_OBJECT_ID = 0x40
ATTR_SECURITY_DESCRIPTOR = 0x50
ATTR_VOLUME_NAME = 0x60
ATTR_VOLUME_INFORMATION = 0x70
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_BITMAP = 0xB0
ATTR_REPARSE_POINT = 0xC0
ATTR_END = 0xFFFFFFFF


def filetime_to_iso(ft: int) -> Optional[str]:
    if ft <= 0 or ft >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        epoch_delta = 116444736000000000
        if ft < epoch_delta:
            return None
        seconds = (ft - epoch_delta) / 10000000.0
        # Sanity check: between 1970 and 2100
        if 0 <= seconds <= 4102444800:
            dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        pass
    return None


@dataclass(slots=True)
class MFTRecord:
    record_number: int
    is_deleted: bool
    is_directory: bool
    filename: str
    parent_record_number: int
    file_size: int
    allocated_size: int
    created_time: Optional[str]
    modified_time: Optional[str]
    accessed_time: Optional[str]
    mft_altered_time: Optional[str]
    raw_offset: int
    resident_data: Optional[bytes] = None
    data_runs: List[Tuple[int, int]] = field(default_factory=list) 
    full_path: str = ""
    attributes_found: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_number": self.record_number,
            "is_deleted": self.is_deleted,
            "is_directory": self.is_directory,
            "filename": self.filename or (f"Directory_{self.record_number}" if self.is_directory else f"Record_{self.record_number}"),
            "full_path": self.full_path or self.filename,
            "parent_record_number": self.parent_record_number,
            "file_size": self.file_size,
            "allocated_size": self.allocated_size,
            "created_time": self.created_time,
            "modified_time": self.modified_time,
            "accessed_time": self.accessed_time,
            "mft_altered_time": self.mft_altered_time,
            "raw_offset": self.raw_offset,
            "raw_offset_hex": f"0x{self.raw_offset:08X}",
            "has_resident_data": self.resident_data is not None and len(self.resident_data) > 0,
            "resident_size": len(self.resident_data) if self.resident_data else 0,
            "data_runs_count": len(self.data_runs),
            "attributes": self.attributes_found,
        }


def apply_fixup_array(raw_record: bytes) -> bytes:
    """
    Apply NTFS Update Sequence Array (USA) fixups across 512-byte sectors.
    Restores the original two bytes at the end of each sector.
    """
    if len(raw_record) < MFT_RECORD_SIZE:
        return raw_record

    record = bytearray(raw_record[:MFT_RECORD_SIZE])
    usa_offset, usa_count = struct.unpack_from("<HH", record, 0x04)
    if usa_offset + usa_count * 2 > len(record) or usa_count < 2:
        return bytes(record)

    usa_check = struct.unpack_from("<H", record, usa_offset)[0]

    sector_size = 512
    num_sectors = len(record) // sector_size

    for i in range(1, min(usa_count, num_sectors + 1)):
        sector_end_offset = (i * sector_size) - 2
        curr_val = struct.unpack_from("<H", record, sector_end_offset)[0]
        if curr_val == usa_check:
            fixup_val = struct.unpack_from("<H", record, usa_offset + (i * 2))[0]
            struct.pack_into("<H", record, sector_end_offset, fixup_val)

    return bytes(record)


def parse_data_runs(run_bytes: bytes) -> List[Tuple[int, int]]:
    """
    Parse NTFS compressed variable-length Data Runlist.
    Returns list of (cluster_count, cluster_lcn).
    """
    runs = []
    idx = 0
    prev_lcn = 0

    while idx < len(run_bytes):
        header = run_bytes[idx]
        idx += 1
        if header == 0:
            break

        len_size = header & 0x0F
        offset_size = (header >> 4) & 0x0F

        if idx + len_size + offset_size > len(run_bytes):
            break

        count_bytes = run_bytes[idx : idx + len_size]
        count = int.from_bytes(count_bytes, byteorder="little", signed=False)
        idx += len_size

        offset_bytes = run_bytes[idx : idx + offset_size]
        offset = int.from_bytes(offset_bytes, byteorder="little", signed=True)
        idx += offset_size

        actual_lcn = prev_lcn + offset
        prev_lcn = actual_lcn

        runs.append((count, actual_lcn))

    return runs


class MFTParser:
    """Forensic NTFS MFT Record Parser and Deleted Item Reconstructor."""

    @classmethod
    def parse_record(cls, raw_data: bytes, raw_offset: int = 0) -> Optional[MFTRecord]:
        """
        Parse a single 1024-byte NTFS MFT Record.
        Returns MFTRecord or None if invalid.
        """
        if len(raw_data) < MFT_RECORD_SIZE or not raw_data.startswith(MFT_RECORD_MAGIC):
            return None

        data = apply_fixup_array(raw_data)

        first_attr_offset, flags = struct.unpack_from("<HH", data, 0x14)
        if first_attr_offset < 0x30 or first_attr_offset >= MFT_RECORD_SIZE:
            return None

        record_num = struct.unpack_from("<I", data, 0x2C)[0] if len(data) >= 0x30 else 0

        is_in_use = bool(flags & 0x0001)
        is_directory = bool(flags & 0x0002)
        is_deleted = not is_in_use

        filename = ""
        parent_rec_num = 0
        file_size = 0
        alloc_size = 0

        c_time = None
        m_time = None
        a_time = None
        r_time = None

        resident_data: Optional[bytes] = None
        data_runs: List[Tuple[int, int]] = []
        attrs_found: List[str] = []

        curr_off = first_attr_offset

        while curr_off + 8 <= len(data):
            attr_type, attr_len = struct.unpack_from("<II", data, curr_off)
            if attr_type == ATTR_END or attr_len == 0 or (curr_off + attr_len) > len(data):
                break

            non_resident = data[curr_off + 8] != 0

            # ── 1. $STANDARD_INFORMATION (0x10) ────
            if attr_type == ATTR_STANDARD_INFORMATION and not non_resident:
                attrs_found.append("$STANDARD_INFORMATION")
                content_len, content_off = struct.unpack_from("<IH", data, curr_off + 16)
                abs_content = curr_off + content_off
                if abs_content + 32 <= len(data) and content_len >= 32:
                    c_raw, m_raw, a_raw, r_raw = struct.unpack_from("<QQQQ", data, abs_content)
                    c_time = filetime_to_iso(c_raw)
                    m_time = filetime_to_iso(m_raw)
                    a_time = filetime_to_iso(a_raw)
                    r_time = filetime_to_iso(r_raw)

            # ── 2. $FILE_NAME (0x30) ───────────────
            elif attr_type == ATTR_FILE_NAME and not non_resident:
                attrs_found.append("$FILE_NAME")
                content_len, content_off = struct.unpack_from("<IH", data, curr_off + 16)
                abs_content = curr_off + content_off
                if abs_content + 66 <= len(data):
                    parent_ref = struct.unpack_from("<Q", data, abs_content)[0]
                    parent_rec = parent_ref & 0x0000FFFFFFFFFFFF  # lower 48 bits = record number

                    alloc_sz, real_sz = struct.unpack_from("<QQ", data, abs_content + 40)
                    fn_len = data[abs_content + 64]
                    fn_namespace = data[abs_content + 65]

                    fn_start = abs_content + 66
                    fn_end = fn_start + (fn_len * 2)

                    if fn_end <= len(data) and fn_len > 0:
                        candidate_name = data[fn_start:fn_end].decode("utf-16le", errors="replace")
                        # Prefer Win32 / POSIX names over DOS 8.3 short names
                        if not filename or fn_namespace in (1, 3):
                            filename = candidate_name
                            parent_rec_num = parent_rec
                            if real_sz > 0 and file_size == 0:
                                file_size = real_sz
                                alloc_size = alloc_sz

            elif attr_type == ATTR_DATA:
                attrs_found.append("$DATA")
                name_len = data[curr_off + 9]
                if name_len == 0:
                    if not non_resident:
                        data_len, data_off = struct.unpack_from("<IH", data, curr_off + 16)
                        abs_data = curr_off + data_off
                        if abs_data + data_len <= len(data):
                            resident_data = data[abs_data : abs_data + data_len]
                            file_size = data_len
                            alloc_size = (data_len + 511) & ~511
                    else:
                        run_off = struct.unpack_from("<H", data, curr_off + 32)[0]
                        real_sz = struct.unpack_from("<Q", data, curr_off + 48)[0]
                        alloc_sz = struct.unpack_from("<Q", data, curr_off + 40)[0]
                        if real_sz > 0:
                            file_size = real_sz
                            alloc_size = alloc_sz
                        abs_runs = curr_off + run_off
                        if abs_runs < (curr_off + attr_len):
                            data_runs = parse_data_runs(data[abs_runs : curr_off + attr_len])

            curr_off += attr_len

        return MFTRecord(
            record_number=record_num,
            is_deleted=is_deleted,
            is_directory=is_directory,
            filename=filename,
            parent_record_number=parent_rec_num,
            file_size=file_size,
            allocated_size=alloc_size,
            created_time=c_time,
            modified_time=m_time,
            accessed_time=r_time,
            mft_altered_time=a_time,
            raw_offset=raw_offset,
            resident_data=resident_data,
            data_runs=data_runs,
            attributes_found=attrs_found,
        )

    @classmethod
    def scan_source(
        cls,
        source_path: str,
        start_offset: int = 0,
        max_bytes: Optional[int] = None,
        max_records: int = 10000,
        progress_cb: Optional[Callable[[int, int, int], None]] = None,
        stop_flag: Optional[List[bool]] = None,
    ) -> List[MFTRecord]:
       
        from .image_readers import reader_for_source
        from pathlib import Path
        clean_path = source_path.replace("/", "\\")
        is_dev = clean_path.startswith("\\\\.\\")
        ext = Path(clean_path).suffix.lower() if not is_dev else ""
        stype = "e01" if ext in (".e01", ".ex01") else ("aff" if ext in (".aff", ".afd") else "file")
        reader = reader_for_source(source_path, stype)

        records: List[MFTRecord] = []
        stop = stop_flag or [False]
        cb = progress_cb or (lambda *_: None)

        with reader:
            total_size = reader.size if reader.size and reader.size > 0 else 0
            scan_len = min(max_bytes, total_size - start_offset) if (max_bytes and total_size > start_offset) else max_bytes or total_size

            chunk_size = 1024 * 1024  # 1 MB chunk
            curr_off = start_offset
            bytes_scanned = 0

            while True:
                if stop[0] or len(records) >= max_records:
                    break

                read_sz = chunk_size
                if max_bytes and (bytes_scanned + read_sz > max_bytes):
                    read_sz = max_bytes - bytes_scanned
                if read_sz <= 0:
                    break

                chunk = reader.read_at(curr_off, read_sz)
                if not chunk:
                    break

                # Scan sector-aligned offsets (512-byte boundaries)
                for i in range(0, len(chunk) - MFT_RECORD_SIZE + 1, 512):
                    if stop[0] or len(records) >= max_records:
                        break
                    if chunk[i : i + 4] == MFT_RECORD_MAGIC:
                        rec = cls.parse_record(chunk[i : i + MFT_RECORD_SIZE], raw_offset=curr_off + i)
                        if rec and (rec.filename or rec.attributes_found):
                            records.append(rec)

                bytes_scanned += len(chunk)
                curr_off += len(chunk)
                cb(bytes_scanned, scan_len, len(records))

                if len(chunk) < read_sz:
                    break

        # Build reconstructed parent directory paths
        cls.reconstruct_paths(records)
        return records

    @classmethod
    def reconstruct_paths(cls, records: List[MFTRecord]):
        """Reconstruct full directory hierarchy from parent record numbers."""
        record_map: Dict[int, MFTRecord] = {r.record_number: r for r in records if r.record_number > 0}

        for r in records:
            if not r.filename:
                continue

            if r.record_number == 5:
                r.full_path = "/"
                continue

            path_parts = [r.filename]
            curr_parent = r.parent_record_number
            depth = 0

            while curr_parent > 5 and curr_parent in record_map and depth < 20:
                p_rec = record_map[curr_parent]
                if p_rec.filename and p_rec.filename not in (".", ".."):
                    path_parts.append(p_rec.filename)
                curr_parent = p_rec.parent_record_number
                depth += 1

            r.full_path = "/" + "/".join(reversed(path_parts))
