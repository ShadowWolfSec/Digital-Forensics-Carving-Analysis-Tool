import os
import tempfile
import unittest
from pathlib import Path

from core.regex_searcher import (
    luhn_checksum,
    identify_card_brand,
    mask_card_number,
    RegexRawSearcher,
    PatternMatch,
)


class TestRegexSearcher(unittest.TestCase):

    def test_luhn_checksum(self):
        self.assertTrue(luhn_checksum("4532015112830366"))  # Valid Visa
        self.assertTrue(luhn_checksum("5425233430109903"))  # Valid Mastercard
        self.assertTrue(luhn_checksum("378282246310005"))   # Valid Amex

        self.assertFalse(luhn_checksum("4532015112830367"))
        self.assertFalse(luhn_checksum("1234567890123456"))

        self.assertFalse(luhn_checksum("12345"))
        self.assertFalse(luhn_checksum("123456789012345678901"))

    def test_identify_card_brand(self):
        self.assertEqual(identify_card_brand("4532015112830366"), "Visa")
        self.assertEqual(identify_card_brand("5425233430109903"), "MasterCard")
        self.assertEqual(identify_card_brand("378282246310005"), "American Express")
        self.assertEqual(identify_card_brand("6011111111111117"), "Discover")

    def test_mask_card_number(self):
        masked = mask_card_number("4532-0151-1283-0366")
        self.assertEqual(masked, "4532-****-****-0366")
        self.assertTrue(masked.startswith("4532"))
        self.assertTrue(masked.endswith("0366"))

    def test_raw_chunk_scanning(self):
        sample_data = (
            b"\x00" * 128
            + b"User record: John Doe, email: john.doe@example.org in server room\n"
            + b"\xAA\xBB\xCC" * 20
            + b"Connecting to target IP 192.168.1.155 on port 8080.\n"
            + b"\x00" * 64
            + b"Wallet BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa transfer verified\n"
            + b"\x00" * 32
            + b"Wallet ETH: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed confirmed\n"
            + b"\x00" * 64
            + b"Emergency contact: +1-800-555-0199 for billing issues\n"
            + b"\x00" * 64
            + b"Card on file: 4532-0151-1283-0366 expires 12/28\n"
            + b"\x00" * 128
        )

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            tmp.write(sample_data)
            tmp_path = tmp.name

        try:
            searcher = RegexRawSearcher(chunk_size=512, overlap=64)
            matches = searcher.search(tmp_path)

            categories = {m.category for m in matches}
            self.assertIn("email", categories)
            self.assertIn("ipv4", categories)
            self.assertIn("crypto", categories)
            self.assertIn("phone", categories)
            self.assertIn("credit_card", categories)

            email_match = next(m for m in matches if m.category == "email")
            self.assertEqual(email_match.value, "john.doe@example.org")

            ip_match = next(m for m in matches if m.category == "ipv4")
            self.assertEqual(ip_match.value, "192.168.1.155")
            self.assertTrue(ip_match.metadata.get("is_private"))

            cc_match = next(m for m in matches if m.category == "credit_card")
            self.assertIn("4532", cc_match.value)
            self.assertEqual(cc_match.label, "Visa")
            self.assertEqual(cc_match.masked_value, "4532-****-****-0366")

            self.assertTrue(len(cc_match.context_text) > 0)
            self.assertTrue(len(cc_match.context_hex) > 0)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
