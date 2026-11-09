import io
import unittest
from core.fuzzy_hasher import FuzzyHasher
from core.perceptual_hasher import PerceptualHasher
from core.byte_differ import ByteDiffer
from PIL import Image, ImageDraw


class TestFuzzyAndDiffer(unittest.TestCase):

    def test_fuzzy_hasher_identical_and_similar(self):
        base_text = (
            b"Forensic Investigation Report Case #102948.\n"
            b"Suspect drive image captured at 14:00 UTC.\n"
            b"Found multiple deleted artifacts in unallocated sectors.\n"
            b"Analyzing cryptographic keys and bitcoin transactions.\n"
        ) * 5

        h1 = FuzzyHasher.compute(base_text)
        h2 = FuzzyHasher.compute(base_text)
        self.assertEqual(FuzzyHasher.compare(h1, h2), 100)

        modified_text = base_text.replace(b"Case #102948", b"Case #102949")
        h3 = FuzzyHasher.compute(modified_text)
        score = FuzzyHasher.compare(h1, h3)
        self.assertGreaterEqual(score, 70)

        diff_text = b"\xFF\xFE\x00\x01\x02\x03\x04\x05" * 40
        h_diff = FuzzyHasher.compute(diff_text)
        diff_score = FuzzyHasher.compare(h1, h_diff)
        self.assertLess(diff_score, 30)

    def test_byte_differ(self):
        data_a = b"AAAA" + b"BBBB" + b"CCCC" + b"DDDD"
        data_b = b"AAAA" + b"XXXX" + b"CCCC" + b"YYYY"

        res = ByteDiffer.diff(data_a, data_b)
        self.assertFalse(res["identical"])
        self.assertEqual(res["differing_bytes"], 8)
        self.assertEqual(res["differing_blocks_count"], 2)

        b0 = res["diff_blocks"][0]
        self.assertEqual(b0["offset"], 4)
        self.assertEqual(b0["length"], 4)
        self.assertIn("42 42 42 42", b0["hex_a"])  # BBBB
        self.assertIn("58 58 58 58", b0["hex_b"])  # XXXX

    def test_perceptual_hasher(self):
        if not PerceptualHasher.is_available():
            self.skipTest("PIL not available")

        img1 = Image.new("RGB", (100, 100), color=(255, 255, 255))
        draw1 = ImageDraw.Draw(img1)
        draw1.rectangle([20, 20, 80, 80], fill=(0, 0, 0))
        bio1 = io.BytesIO()
        img1.save(bio1, format="PNG")
        bytes1 = bio1.getvalue()

        cmp_self = PerceptualHasher.compare_images(bytes1, bytes1)
        self.assertTrue(cmp_self["is_identical"])
        self.assertEqual(cmp_self["composite_similarity"], 100.0)

        img2 = img1.copy()
        draw2 = ImageDraw.Draw(img2)
        draw2.point([50, 50], fill=(255, 0, 0))
        bio2 = io.BytesIO()
        img2.save(bio2, format="JPEG", quality=90)
        bytes2 = bio2.getvalue()

        cmp_mod = PerceptualHasher.compare_images(bytes1, bytes2)
        self.assertGreaterEqual(cmp_mod["composite_similarity"], 80.0)


if __name__ == "__main__":
    unittest.main()
