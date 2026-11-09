import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from core.models import (
    CarvedFile,
    FileSignature,
    HashBundle,
    EntropyResult,
    ValidationResult,
    CustodyEntry,
    ScanResult,
)
from core.mft_parser import MFTRecord
from core.regex_searcher import PatternMatch
from core.reporter import save_json, save_csv, save_html, save_jsonl, seal_report
from web import create_app
from web.state import _get_carved_filename


class TestAuditHardening(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.temp_dir.name)

        self.dummy_sig = FileSignature(
            id="jpg",
            name="JPEG Image",
            description="Joint Photographic Experts Group",
            category="Images",
            extensions=["jpg", "jpeg"],
            mime_type="image/jpeg",
            header=b"\xFF\xD8\xFF",
            trailer=b"\xFF\xD9",
            confidence=0.9,
        )
        self.dummy_file = CarvedFile(
            id=1,
            signature=self.dummy_sig,
            start_offset=0x1000,
            end_offset=0x2000,
            size=4096,
            confidence=0.95,
            header_hex="FF D8 FF",
            trailer_hex="FF D9",
            recovery_status="COMPLETE",
            validation=ValidationResult(True, "Valid JPEG image structure"),
            hashes=HashBundle("d41d8cd98f00b204e9800998ecf8427e", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            entropy=EntropyResult(7.5, "compressed", False, True),
            metadata={"source_file": "sample.dd"},
        )
        self.dummy_result = ScanResult(
            source_path="sample.dd",
            source_type="raw",
            source_hash=HashBundle("md5", "sha1", "sha256"),
            start_time=None,
            end_time=None,
            blocks_scanned=10,
            bytes_scanned=40960,
            carved_files=[self.dummy_file],
            custody_log=[CustodyEntry.now("Acquisition", "analyst", "Evidence verified")],
            errors=[],
        )

    def tearDown(self):
        self.temp_dir.cleanup()

  

    def test_mft_record_has_slots_and_no_dict(self):
        rec = MFTRecord(
            record_number=42,
            is_deleted=True,
            is_directory=False,
            filename="deleted_invoice.pdf",
            parent_record_number=5,
            file_size=1024,
            allocated_size=4096,
            created_time=None,
            modified_time=None,
            accessed_time=None,
            mft_altered_time=None,
            raw_offset=0x4000,
        )
        self.assertTrue(hasattr(rec, "__slots__"))
        self.assertFalse(hasattr(rec, "__dict__"), "MFTRecord should not have a dynamic __dict__")

    def test_pattern_match_has_slots(self):
        pm = PatternMatch(
            id=1,
            category="credit_card",
            label="Visa",
            value="4532015112830366",
            masked_value="4532-****-****-0366",
            offset=100,
            offset_hex="0x00000064",
            source_file="disk.img",
            context_text="...",
            context_hex="...",
        )
        self.assertTrue(hasattr(pm, "__slots__"))
        self.assertFalse(hasattr(pm, "__dict__"), "PatternMatch should not have a dynamic __dict__")

    def test_carved_file_has_slots(self):
        self.assertTrue(hasattr(self.dummy_file, "__slots__"))
        self.assertFalse(hasattr(self.dummy_file, "__dict__"), "CarvedFile should not have a dynamic __dict__")


    def test_save_json_cryptographic_seal(self):
        out_file = self.out_dir / "report.json"
        save_json(self.dummy_result, str(out_file))

        self.assertTrue(out_file.is_file())
        seal_file = out_file.with_name("report.json.sha256")
        self.assertTrue(seal_file.is_file(), "A companion .sha256 seal must be generated")

        expected_hash = hashlib.sha256(out_file.read_bytes()).hexdigest()
        seal_content = seal_file.read_text(encoding="utf-8").strip()
        self.assertEqual(seal_content, f"{expected_hash}  report.json")

    def test_save_csv_cryptographic_seal(self):
        out_file = self.out_dir / "report.csv"
        save_csv(self.dummy_result, str(out_file))

        self.assertTrue(out_file.is_file())
        seal_file = out_file.with_name("report.csv.sha256")
        self.assertTrue(seal_file.is_file())

        expected_hash = hashlib.sha256(out_file.read_bytes()).hexdigest()
        seal_content = seal_file.read_text(encoding="utf-8").strip()
        self.assertEqual(seal_content, f"{expected_hash}  report.csv")

    def test_save_html_cryptographic_seal(self):
        out_file = self.out_dir / "report.html"
        save_html(self.dummy_result, str(out_file), case_name="Case #101")

        self.assertTrue(out_file.is_file())
        seal_file = out_file.with_name("report.html.sha256")
        self.assertTrue(seal_file.is_file())

        expected_hash = hashlib.sha256(out_file.read_bytes()).hexdigest()
        seal_content = seal_file.read_text(encoding="utf-8").strip()
        self.assertEqual(seal_content, f"{expected_hash}  report.html")


    def test_save_jsonl_streaming_and_sealing(self):
        out_file = self.out_dir / "report.jsonl"
        save_jsonl(self.dummy_result, str(out_file))

        self.assertTrue(out_file.is_file())
        seal_file = out_file.with_name("report.jsonl.sha256")
        self.assertTrue(seal_file.is_file())

        # Verify newline-delimited JSON structure
        lines = out_file.read_text(encoding="utf-8").strip().splitlines()
        self.assertGreaterEqual(len(lines), 3)  # header + custody + carved_file

        header = json.loads(lines[0])
        self.assertEqual(header.get("record_type"), "header")
        self.assertEqual(header.get("tool"), "Digital Forensics Tool v2.0")

        custody = json.loads(lines[1])
        self.assertEqual(custody.get("record_type"), "custody")
        self.assertEqual(custody["data"]["action"], "Acquisition")

        file_rec = json.loads(lines[2])
        self.assertEqual(file_rec.get("record_type"), "carved_file")
        self.assertEqual(file_rec["data"]["id"], 1)



    def test_web_security_headers_present(self):
        app = create_app({"TESTING": True})
        client = app.test_client()
        resp = client.get("/")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("X-XSS-Protection"), "1; mode=block")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("default-src 'self'", resp.headers.get("Content-Security-Policy", ""))

  

    def test_filename_sanitization_and_containment(self):
        fname = _get_carved_filename(self.dummy_file)
        self.assertNotIn("/", fname)
        self.assertNotIn("\\", fname)
        self.assertNotIn("..", fname)

        # Ensure containment inside destination directory
        target_dir = self.out_dir / "exports"
        target_dir.mkdir(parents=True, exist_ok=True)
        file_path = (target_dir / fname).resolve()
        self.assertTrue(file_path.is_relative_to(target_dir.resolve()))

  

    def test_timeline_analyzer_mixed_timezone_awareness(self):
        from core.timeline import TimelineAnalyzer, _parse_ts
        from datetime import datetime, timezone

        res = ScanResult(
            source_path="evidence.raw",
            source_type="raw",
            source_hash=None,
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            blocks_scanned=10,
            bytes_scanned=40960,
            carved_files=[self.dummy_file],
            custody_log=[
                CustodyEntry("2026-11-08T12:00:00Z", "Acquisition", "analyst", "Step 1"),
                CustodyEntry("2026-11-08 13:00:00", "Verification", "analyst", "Step 2"),
                CustodyEntry("2026-11-08T14:00:00.123456+00:00", "Hashing", "analyst", "Step 3"),
                CustodyEntry("invalid-timestamp-string", "Note", "analyst", "Step 4"),
            ],
            errors=[],
        )

        events = TimelineAnalyzer.build(res)
        self.assertGreaterEqual(len(events), 5)

        parsed_dates = [_parse_ts(e.timestamp) for e in events]
        for dt in parsed_dates:
            self.assertIsNotNone(dt.tzinfo, "All parsed datetimes must be timezone-aware (tzinfo not None)")
            self.assertEqual(dt.tzinfo, timezone.utc)

        self.assertTrue(all(parsed_dates[i] <= parsed_dates[i + 1] for i in range(len(parsed_dates) - 1)))

    def test_scan_stopped_retains_results(self):
        from web.state import _run_scan_thread, _STATE, _SCAN_STATE, _SCAN_STOP_FLAG
        from sdk import ForensicsCarver

        test_file = self.out_dir / "test_disk.bin"
        test_file.write_bytes(b"\x00" * 512 + b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00" + b"\x00" * 100 + b"\xFF\xD9" + b"\x00" * 512)

        carver = ForensicsCarver()
        _SCAN_STOP_FLAG[0] = True  
        _STATE["last_result"] = None

        _run_scan_thread(
            carver=carver,
            source_path=str(test_file),
            source_type="file",
            max_bytes=None,
            start_offset=0,
            recover_fragments=False,
            scan_mode="fast",
            output_dir=str(self.out_dir / "out_reports"),
        )

        self.assertIsNotNone(_STATE["last_result"], "Scan results must be preserved even if stopped by user")
        self.assertEqual(_SCAN_STATE["status"], "stopped")
        self.assertIsNone(_SCAN_STATE.get("error"))


if __name__ == "__main__":
    unittest.main()
