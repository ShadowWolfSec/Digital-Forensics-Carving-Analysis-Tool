import struct
import unittest
from core.mft_parser import (
    MFTParser,
    MFTRecord,
    filetime_to_iso,
    apply_fixup_array,
    MFT_RECORD_SIZE,
    ATTR_STANDARD_INFORMATION,
    ATTR_FILE_NAME,
    ATTR_DATA,
    ATTR_END,
)


def build_synthetic_mft_record(
    filename: str = "Secret_Evidence.pdf",
    is_deleted: bool = True,
    is_directory: bool = False,
    record_number: int = 42,
    parent_record: int = 5,
    payload: bytes = b"Top secret carved data",
) -> bytes:
    """Construct a valid 1024-byte NTFS MFT record for testing."""
    rec = bytearray(MFT_RECORD_SIZE)

    rec[0:4] = b"FILE"
    struct.pack_into("<HH", rec, 0x04, 0x30, 3)     
    struct.pack_into("<Q", rec, 0x08, 123456)       
    struct.pack_into("<HH", rec, 0x10, 1, 1)        

    first_attr = 0x38
    flags = 0
    if not is_deleted:
        flags |= 0x0001
    if is_directory:
        flags |= 0x0002
    struct.pack_into("<HH", rec, 0x14, first_attr, flags)
    struct.pack_into("<II", rec, 0x18, 512, 1024)   
    struct.pack_into("<Q", rec, 0x20, 0)           
    struct.pack_into("<H", rec, 0x28, 4)           
    struct.pack_into("<I", rec, 0x2C, record_number) 

    struct.pack_into("<H", rec, 0x30, 0xABCD)       

    curr = first_attr

    std_content_len = 48
    std_attr_len = 24 + std_content_len
    struct.pack_into("<II", rec, curr, ATTR_STANDARD_INFORMATION, std_attr_len)
    rec[curr + 8] = 0  # Resident
    struct.pack_into("<IH", rec, curr + 16, std_content_len, 24)  # Content len, offset
    test_ft = 134205552000000000
    struct.pack_into("<QQQQ", rec, curr + 24, test_ft, test_ft, test_ft, test_ft)
    curr += std_attr_len

    fn_bytes = filename.encode("utf-16le")
    fn_len_chars = len(filename)
    fn_content_len = 66 + len(fn_bytes)
    fn_attr_len = ((24 + fn_content_len + 7) & ~7)  # 8-byte aligned

    struct.pack_into("<II", rec, curr, ATTR_FILE_NAME, fn_attr_len)
    rec[curr + 8] = 0  
    struct.pack_into("<IH", rec, curr + 16, fn_content_len, 24)
    abs_fn = curr + 24
    struct.pack_into("<Q", rec, abs_fn, parent_record) # Parent directory
    struct.pack_into("<QQ", rec, abs_fn + 40, len(payload), len(payload))
    rec[abs_fn + 64] = fn_len_chars
    rec[abs_fn + 65] = 1 
    rec[abs_fn + 66 : abs_fn + 66 + len(fn_bytes)] = fn_bytes
    curr += fn_attr_len

    data_content_len = len(payload)
    data_attr_len = ((24 + data_content_len + 7) & ~7)
    struct.pack_into("<II", rec, curr, ATTR_DATA, data_attr_len)
    rec[curr + 8] = 0 
    struct.pack_into("<IH", rec, curr + 16, data_content_len, 24)
    rec[curr + 24 : curr + 24 + len(payload)] = payload
    curr += data_attr_len

    struct.pack_into("<I", rec, curr, ATTR_END)
    return bytes(rec)


class TestMFTParser(unittest.TestCase):

    def test_filetime_conversion(self):
        ft = 134205552000000000
        iso_str = filetime_to_iso(ft)
        self.assertIsNotNone(iso_str)
        self.assertIn("UTC", iso_str)

        self.assertIsNone(filetime_to_iso(0))
        self.assertIsNone(filetime_to_iso(-100))

    def test_parse_deleted_record(self):
        raw = build_synthetic_mft_record(
            filename="Confidential_Report.docx",
            is_deleted=True,
            record_number=105,
            parent_record=5,
            payload=b"Secret content inside resident stream",
        )

        rec = MFTParser.parse_record(raw, raw_offset=4096)
        self.assertIsNotNone(rec)
        self.assertTrue(rec.is_deleted)
        self.assertEqual(rec.record_number, 105)
        self.assertEqual(rec.filename, "Confidential_Report.docx")
        self.assertEqual(rec.parent_record_number, 5)
        self.assertIsNotNone(rec.created_time)
        self.assertEqual(rec.resident_data, b"Secret content inside resident stream")
        self.assertEqual(rec.file_size, len(b"Secret content inside resident stream"))

    def test_directory_tree_reconstruction(self):
        folder_raw = build_synthetic_mft_record(
            filename="Documents",
            is_deleted=False,
            is_directory=True,
            record_number=10,
            parent_record=5,
        )
        rec_folder = MFTParser.parse_record(folder_raw)

        file_raw = build_synthetic_mft_record(
            filename="Budget.xlsx",
            is_deleted=True,
            is_directory=False,
            record_number=25,
            parent_record=10,
        )
        rec_file = MFTParser.parse_record(file_raw)

        records = [rec_folder, rec_file]
        MFTParser.reconstruct_paths(records)

        self.assertEqual(rec_folder.full_path, "/Documents")
        self.assertEqual(rec_file.full_path, "/Documents/Budget.xlsx")


if __name__ == "__main__":
    unittest.main()
