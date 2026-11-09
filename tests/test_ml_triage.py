import io
import unittest
from PIL import Image, ImageDraw
from core.ml_triage import (
    DocumentSemanticClassifier,
    ExecutableRiskClassifier,
    VisionContentClassifier,
    MLTriageEngine,
)
from core.ai_triage import AITriageEngine, TriageResult
from core.models import CarvedFile, FileSignature, EntropyResult, ValidationResult


class TestMLTriage(unittest.TestCase):

    def test_document_semantic_classifier(self):
        fin_text = "INVOICE #9482. Total Due: $45,000. Please process wire transfer to IBAN GB29X and account statement."
        res_fin = DocumentSemanticClassifier.classify_text(fin_text)
        self.assertEqual(res_fin["top_topic"], "financial")
        self.assertGreaterEqual(res_fin["confidence"], 0.5)

        cred_text = "api_key = 'sk_live_9921820491823' and master_key for private_key authorization with password."
        res_cred = DocumentSemanticClassifier.classify_text(cred_text)
        self.assertEqual(res_cred["top_topic"], "credentials")

        # 3.  Text
        conf_text = "STRICTLY PRIVATE AND CONFIDENTIAL. Internal use only board memo. Do not disclose trade secret."
        res_conf = DocumentSemanticClassifier.classify_text(conf_text)
        self.assertEqual(res_conf["top_topic"], "confidential_internal")

    def test_executable_risk_classifier(self):
        pe_bytes = (
            b"MZ" + b"\x00" * 60 + b"\x80\x00\x00\x00"
            + b"\x00" * 58
            + b"PE\x00\x00"
            + b"UPX0\x00\x00\x00\x00"
            + b"\x00" * 200
            + b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"
            + b"\xFF" * 500
        )
        res_pe = ExecutableRiskClassifier.analyze(pe_bytes)
        self.assertTrue(res_pe["is_executable"])
        self.assertEqual(res_pe["packer"], "UPX0")
        self.assertIn("process_injection", res_pe["capabilities"])
        self.assertGreaterEqual(res_pe["risk_score"], 0.70)

    def test_vision_content_classifier(self):
        img = Image.new("RGB", (200, 200), color=(250, 250, 250))
        draw = ImageDraw.Draw(img)
        for y in range(20, 180, 15):
            draw.line([20, y, 180, y], fill=(10, 10, 10), width=2)
        bio = io.BytesIO()
        img.save(bio, format="PNG")
        res_vis = VisionContentClassifier.analyze(bio.getvalue())
        self.assertEqual(res_vis["category"], "document_scan")

    def test_ai_triage_engine_integration(self):
        sig = FileSignature(
            id="text",
            name="Plain Text",
            description="Text Document",
            category="document",
            extensions=["txt"],
            mime_type="text/plain",
            header=b"",
        )
        cf = CarvedFile(
            id=1,
            signature=sig,
            start_offset=1024,
            end_offset=1524,
            size=500,
            confidence=0.95,
            header_hex="",
            trailer_hex="",
            recovery_status="COMPLETE",
            validation=ValidationResult(True, "Valid"),
        )

        secret_data = b"Confidential DB: api_key = '99120481239' and root password = 'SuperSecretPassword123!'"
        engine = AITriageEngine()
        result = engine.classify(cf, secret_data)

        self.assertIsInstance(result, TriageResult)
        self.assertIn(result.priority, ("critical", "high"))
        self.assertEqual(result.doc_topic, "credentials")
        self.assertGreaterEqual(result.threat_score, 70)
        self.assertTrue(len(result.reasons) > 0)


if __name__ == "__main__":
    unittest.main()
