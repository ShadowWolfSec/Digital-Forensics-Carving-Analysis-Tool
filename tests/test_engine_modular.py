import io
import struct
import tempfile
import unittest
from pathlib import Path

from core.source_detector import detect_source_type, is_physical_drive, is_disk_image_extension
from core.custody import CustodyManager
from core.metadata_extractors import extract_basic_metadata, extract_file_metadata
from core.signatures import FileSignature


class TestEngineModularComponents(unittest.TestCase):

    def test_source_detector(self):
        self.assertTrue(is_physical_drive(r"\\.\PhysicalDrive0"))
        self.assertTrue(is_physical_drive("/dev/sdb"))
        self.assertEqual(detect_source_type(r"\\.\PhysicalDrive1"), "physical_drive")
        self.assertEqual(detect_source_type("/dev/sda"), "physical_drive")

        self.assertTrue(is_disk_image_extension(".raw"))
        self.assertTrue(is_disk_image_extension(".001"))
        self.assertTrue(is_disk_image_extension(".dd"))
        self.assertFalse(is_disk_image_extension(".txt"))

        with tempfile.TemporaryDirectory() as tmp_dir:
            self.assertEqual(detect_source_type(tmp_dir), "directory")

            mbr_path = Path(tmp_dir) / "sample_mbr.bin"
            mbr_data = bytearray(512)
            mbr_data[510] = 0x55
            mbr_data[511] = 0xAA
            mbr_path.write_bytes(mbr_data)
            self.assertEqual(detect_source_type(str(mbr_path)), "disk_image")

            txt_path = Path(tmp_dir) / "normal.txt"
            txt_path.write_text("plain evidence note", encoding="utf-8")
            self.assertEqual(detect_source_type(str(txt_path)), "file")

    def test_custody_manager(self):
        cm = CustodyManager(analyst="Lead Investigator")
        self.assertEqual(len(cm), 0)

        entry1 = cm.log(action="Evidence loaded", details="Case #1024", source_hash="sha256:abc")
        self.assertEqual(entry1.action, "Evidence loaded")
        self.assertEqual(entry1.analyst, "Lead Investigator")
        self.assertEqual(entry1.source_hash, "sha256:abc")
        self.assertEqual(len(cm.entries), 1)

        cm.log(action="Carving complete")
        self.assertEqual(len(cm.entries), 2)

        dicts = cm.to_dict_list()
        self.assertEqual(len(dicts), 2)
        self.assertEqual(dicts[0]["action"], "Evidence loaded")

        cm.reset()
        self.assertEqual(len(cm.entries), 0)

    def test_metadata_extraction(self):
        png_data = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(">II", 1920, 1080) + b"\x00" * 20
        res_png = extract_basic_metadata(png_data, validator="validate_png")
        self.assertEqual(res_png.get("width"), 1920)
        self.assertEqual(res_png.get("height"), 1080)
        self.assertEqual(res_png.get("dimensions"), "1920x1080")

        pe_data = bytearray(128)
        pe_data[0:2] = b"MZ"
        struct.pack_into("<I", pe_data, 60, 64)  
        pe_data[64:68] = b"PE\x00\x00"
        struct.pack_into("<H", pe_data, 68, 0x8664)  # x64 machine
        res_pe = extract_basic_metadata(bytes(pe_data), validator="validate_pe")
        self.assertEqual(res_pe.get("arch"), "x64")
        self.assertEqual(res_pe.get("machine"), "0x8664")

        sig = FileSignature(
            id="png",
            name="Portable Network Graphics",
            description="PNG image",
            category="image",
            extensions=["png"],
            mime_type="image/png",
            header=b"\x89PNG\r\n\x1a\n",
            validator="validate_png",
        )
        unified_meta = extract_file_metadata(png_data, sig)
        self.assertEqual(unified_meta.get("dimensions"), "1920x1080")


if __name__ == "__main__":
    unittest.main()
