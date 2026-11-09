import json
import os
import tempfile
import unittest
from gui_app import app


class TestSearchEndpoints(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

        self.sample_data = (
            b"\x00" * 32
            + b"contact: admin@forensics.corp and IP 10.0.0.1\n"
            + b"credit: 4532-0151-1283-0366 expires soon\n"
            + b"\x00" * 32
        )
        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        self.tmp.write(self.sample_data)
        self.tmp.close()

    def tearDown(self):
        if os.path.exists(self.tmp.name):
            os.remove(self.tmp.name)

    def test_search_page_get(self):
        res = self.app.get("/search")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Pattern & PII Search", res.data)

    def test_search_lifecycle(self):
        res = self.app.post(
            "/api/search/start",
            json={
                "source_path": self.tmp.name,
                "patterns": ["credit_card", "email", "ipv4"],
                "start_offset": 0,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))

        # Wait for thread to finish
        import time
        for _ in range(20):
            p_res = self.app.get("/api/search/progress")
            p_data = p_res.get_json()
            if p_data.get("status") in ("completed", "stopped"):
                break
            time.sleep(0.1)

        r_res = self.app.get("/api/search/results")
        self.assertEqual(r_res.status_code, 200)
        r_data = r_res.get_json()
        self.assertTrue(r_data.get("ok"))
        self.assertGreater(r_data.get("count"), 0)

        csv_res = self.app.get("/api/search/export?fmt=csv")
        self.assertEqual(csv_res.status_code, 200)
        self.assertIn("text/csv", csv_res.content_type)
        self.assertIn(b"admin@forensics.corp", csv_res.data)

        json_res = self.app.get("/api/search/export?fmt=json")
        self.assertEqual(json_res.status_code, 200)
        self.assertIn("application/json", json_res.content_type)


if __name__ == "__main__":
    unittest.main()
