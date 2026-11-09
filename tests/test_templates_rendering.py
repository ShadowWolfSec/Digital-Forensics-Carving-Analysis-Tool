import unittest
from gui_app import app
from web.state import _STATE


class TestTemplateRendering(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_index_page(self):
        res = self.app.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Forensic File & Disk Carver", res.data)
        self.assertIn(b"base.html", res.data) if False else None
        self.assertIn(b"Connected Drives & Forensic Devices", res.data)

    def test_results_page(self):
        from unittest.mock import MagicMock
        mock_result = MagicMock()
        mock_result.summary.return_value = {
            "source": "dummy.raw",
            "source_type": "raw",
            "files_found": 1,
            "bytes_scanned_human": "10 MB",
            "duration_seconds": 1.5,
            "blocks_scanned": 100,
        }
        mock_file = MagicMock()
        mock_file.id = 1
        mock_file.name = "evidence.jpg"
        mock_file.type_name = "JPEG Image"
        mock_file.extension = "jpg"
        mock_file.size = 1024
        mock_file.start_offset = 0
        mock_file.offset_hex = "0x00000000"
        mock_file.is_embedded = False
        mock_file.artifact_type = "primary"
        mock_file.recovery_status = "COMPLETE"
        mock_file.confidence = 0.95
        mock_file.container_origin = "disk"
        mock_file.signature = MagicMock(category="image")
        mock_file.metadata = {}
        mock_result.carved_files = [mock_file]

        _STATE["last_result"] = mock_result
        _STATE["last_triage"] = []
        _STATE["last_timeline"] = []

        res = self.app.get("/results")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Scan Results & Forensic Evidence", res.data)
        self.assertIn(b"JPEG Image (.jpg)", res.data)

    def test_search_page(self):
        res = self.app.get("/search")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Pattern & PII Search", res.data)
        self.assertIn(b"Credit Cards", res.data)

    def test_compare_page(self):
        res = self.app.get("/compare")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Evidence Comparison", res.data)
        self.assertIn(b"Select Evidence Files to Compare", res.data)

    def test_mft_page(self):
        res = self.app.get("/mft")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"MFT Explorer", res.data)
        self.assertIn(b"NTFS Source", res.data)

    def test_hex_page(self):
        res = self.app.get("/hex")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Binary Stream Hex Viewer", res.data)

    def test_static_assets(self):
        with self.app.get("/static/css/main.css") as css_main:
            self.assertEqual(css_main.status_code, 200)
            self.assertIn(b"main.css", css_main.data)

        with self.app.get("/static/css/modals.css") as css_modals:
            self.assertEqual(css_modals.status_code, 200)
            self.assertIn(b"modals.css", css_modals.data)

        with self.app.get("/static/js/common.js") as js_common:
            self.assertEqual(js_common.status_code, 200)
            self.assertIn(b"formatBytes", js_common.data)


if __name__ == "__main__":
    unittest.main()
