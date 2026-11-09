import os
import tempfile
import time
import unittest
from gui_app import app
from tests.test_mft_parser import build_synthetic_mft_record


class TestMFTEndpoints(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

        rec1 = build_synthetic_mft_record(
            filename="Deleted_Contract.docx",
            is_deleted=True,
            record_number=101,
            payload=b"Contract agreement between party A and B.",
        )
        rec2 = build_synthetic_mft_record(
            filename="System_File.sys",
            is_deleted=False,
            record_number=102,
            payload=b"OS Kernel module.",
        )

        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".raw")
        self.tmp.write(rec1 + rec2)
        self.tmp.close()

    def tearDown(self):
        if os.path.exists(self.tmp.name):
            os.remove(self.tmp.name)

    def test_mft_page_get(self):
        res = self.app.get("/mft")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"MFT Explorer", res.data)

    def test_mft_scan_and_export_lifecycle(self):
        res = self.app.post(
            "/api/mft/start",
            json={"source_path": self.tmp.name},
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))

        for _ in range(25):
            p_res = self.app.get("/api/mft/progress")
            p_data = p_res.get_json()
            if p_data.get("status") in ("completed", "stopped"):
                break
            time.sleep(0.1)

        r_res = self.app.get("/api/mft/results")
        self.assertEqual(r_res.status_code, 200)
        r_data = r_res.get_json()
        self.assertTrue(r_data.get("ok"))
        self.assertEqual(r_data.get("total"), 2)

        del_res = self.app.get("/api/mft/results?filter=deleted")
        del_data = del_res.get_json()
        self.assertEqual(del_data.get("count"), 1)
        self.assertEqual(del_data["records"][0]["filename"], "Deleted_Contract.docx")

        ext_res = self.app.get("/api/mft/extract/101")
        self.assertEqual(ext_res.status_code, 200)
        self.assertIn(b"Contract agreement", ext_res.data)

        csv_res = self.app.get("/api/mft/export?fmt=csv")
        self.assertEqual(csv_res.status_code, 200)
        self.assertIn("text/csv", csv_res.content_type)
        self.assertIn(b"Deleted_Contract.docx", csv_res.data)

        json_res = self.app.get("/api/mft/export?fmt=json")
        self.assertEqual(json_res.status_code, 200)
        self.assertIn("application/json", json_res.content_type)


if __name__ == "__main__":
    unittest.main()
