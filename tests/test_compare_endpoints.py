import io
import json
import os
import tempfile
import unittest
from PIL import Image, ImageDraw
from gui_app import app


class TestCompareEndpoints(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

        self.data_a = (b"Forensic Evidence Report Alpha.\nArtifact details and timestamps.\n") * 6
        self.data_b = (b"Forensic Evidence Report Beta.\nArtifact details and timestamps.\n") * 6

        self.tmp_a = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        self.tmp_a.write(self.data_a)
        self.tmp_a.close()

        self.tmp_b = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        self.tmp_b.write(self.data_b)
        self.tmp_b.close()

    def tearDown(self):
        if os.path.exists(self.tmp_a.name):
            os.remove(self.tmp_a.name)
        if os.path.exists(self.tmp_b.name):
            os.remove(self.tmp_b.name)

    def test_compare_page_get(self):
        res = self.app.get("/compare")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Evidence Comparison", res.data)

    def test_compare_api_files(self):
        res_ident = self.app.post(
            "/api/compare",
            json={"path_a": self.tmp_a.name, "path_b": self.tmp_a.name},
        )
        self.assertEqual(res_ident.status_code, 200)
        d_ident = res_ident.get_json()
        self.assertTrue(d_ident["ok"])
        self.assertTrue(d_ident["hash_match"]["sha256"])
        self.assertEqual(d_ident["fuzzy_similarity"], 100)
        self.assertTrue(d_ident["byte_diff"]["identical"])

        res_diff = self.app.post(
            "/api/compare",
            json={"path_a": self.tmp_a.name, "path_b": self.tmp_b.name},
        )
        self.assertEqual(res_diff.status_code, 200)
        d_diff = res_diff.get_json()
        self.assertTrue(d_diff["ok"])
        self.assertFalse(d_diff["hash_match"]["sha256"])
        self.assertGreater(d_diff["fuzzy_similarity"], 50)
        self.assertFalse(d_diff["byte_diff"]["identical"])
        self.assertGreater(d_diff["byte_diff"]["differing_bytes"], 0)

    def test_compare_api_images(self):
        img1 = Image.new("RGB", (60, 60), color=(255, 255, 255))
        draw1 = ImageDraw.Draw(img1)
        draw1.rectangle([10, 10, 50, 50], fill=(0, 0, 255))
        tmp_img1 = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
        img1.save(tmp_img1, format="PNG")
        tmp_img1.close()

        img2 = img1.copy()
        draw2 = ImageDraw.Draw(img2)
        draw2.point([30, 30], fill=(255, 0, 0))
        tmp_img2 = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg")
        img2.save(tmp_img2, format="JPEG")
        tmp_img2.close()

        try:
            res = self.app.post(
                "/api/compare",
                json={"path_a": tmp_img1.name, "path_b": tmp_img2.name},
            )
            self.assertEqual(res.status_code, 200)
            d = res.get_json()
            self.assertTrue(d["ok"])
            self.assertIsNotNone(d.get("image_comparison"))
            self.assertGreaterEqual(d["image_comparison"]["composite_similarity"], 80.0)
        finally:
            if os.path.exists(tmp_img1.name):
                os.remove(tmp_img1.name)
            if os.path.exists(tmp_img2.name):
                os.remove(tmp_img2.name)


if __name__ == "__main__":
    unittest.main()
