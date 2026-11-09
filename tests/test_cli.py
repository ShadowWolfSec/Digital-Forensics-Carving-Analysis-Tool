import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestCLI(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)
        self.cli_path = str(Path(__file__).resolve().parent.parent / "cli.py")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cli_help(self):
        proc = subprocess.run([sys.executable, self.cli_path, "--help"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("scan", proc.stdout)
        self.assertIn("search", proc.stdout)
        self.assertIn("mft", proc.stdout)
        self.assertIn("sigs", proc.stdout)

    def test_cli_sigs_list(self):
        proc = subprocess.run([sys.executable, self.cli_path, "sigs", "list"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Loaded Signatures", proc.stdout)
        self.assertIn("ARCHIVE", proc.stdout)
        self.assertIn("IMAGE", proc.stdout)

    def test_cli_search_sensitive_data(self):
        sample = self.dir_path / "evidence_search.bin"
        sample.write_bytes(
            b"Log entry: user card 4532015112830366, email analyst@forensics.org, ip 10.0.0.1"
        )
        out_json = self.dir_path / "search_matches.json"

        proc = subprocess.run(
            [sys.executable, self.cli_path, "search", str(sample), "-o", str(out_json), "--context"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"CLI stderr: {proc.stderr}")
        self.assertIn("Matches Found", proc.stdout)
        self.assertTrue(out_json.is_file())
        # Verify companion sha256
        self.assertTrue(out_json.with_name(out_json.name + ".sha256").is_file())

    def test_cli_mft_scan(self):
        sample = self.dir_path / "dummy_mft.bin"
        sample.write_bytes(b"\x00" * 4096)
        out_json = self.dir_path / "mft_records.json"

        proc = subprocess.run(
            [sys.executable, self.cli_path, "mft", str(sample), "-o", str(out_json)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"CLI stderr: {proc.stderr}")
        self.assertIn("NTFS Master File Table", proc.stdout)

    def test_cli_scan_with_all_reports_and_recover(self):
        sample = self.dir_path / "carve_target.bin"
        # 512 bytes noise + JPEG + 512 bytes noise
        sample.write_bytes(
            b"\x00" * 512 + b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00" + b"\x55" * 100 + b"\xFF\xD9" + b"\x00" * 512
        )
        out_dir = self.dir_path / "scan_output"

        proc = subprocess.run(
            [
                sys.executable,
                self.cli_path,
                "scan",
                str(sample),
                "-o",
                str(out_dir),
                "--recover",
                "--format",
                "all",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"CLI stderr: {proc.stderr}")
        self.assertIn("Scan Complete", proc.stdout)
        self.assertIn("Recovered 1 files", proc.stdout)

        # Check recovered directory
        recovered_files = list((out_dir / "recovered").glob("*.jpg"))
        self.assertEqual(len(recovered_files), 1)

        # Check recovered manifest + seal
        manifest = out_dir / "recovered" / "recovered_manifest.json"
        self.assertTrue(manifest.is_file())
        self.assertTrue(manifest.with_name(manifest.name + ".sha256").is_file())

        # Check reports generated
        self.assertTrue(any(out_dir.glob("report_*.json")))
        self.assertTrue(any(out_dir.glob("report_*.jsonl")))
        self.assertTrue(any(out_dir.glob("report_*.csv")))
        self.assertTrue(any(out_dir.glob("report_*.html")))
        # All report companion seals exist
        self.assertTrue(any(out_dir.glob("report_*.json.sha256")))
        self.assertTrue(any(out_dir.glob("report_*.jsonl.sha256")))


if __name__ == "__main__":
    unittest.main()
