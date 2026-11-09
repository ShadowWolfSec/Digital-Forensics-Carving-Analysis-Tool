from __future__ import annotations

import io
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False



DOCUMENT_TOPIC_KEYWORDS = {
    "credentials": {
        "password": 3.0, "passwd": 3.0, "api_key": 4.0, "apikey": 4.0, "secret_key": 4.0,
        "access_token": 3.5, "private_key": 4.5, "id_rsa": 4.5, "bearer": 2.5,
        "authorization": 2.0, "credentials": 3.0, "database_password": 4.0, "db_pass": 4.0,
        "ssh-rsa": 4.5, "seed_phrase": 4.5, "privatekey": 4.0, "token": 2.0,
        "client_secret": 4.0, "master_key": 4.0, "passphrase": 3.5,
    },
    "financial": {
        "invoice": 3.5, "payment": 3.0, "bank": 2.5, "account": 2.0, "iban": 4.0,
        "swift": 3.5, "wire transfer": 4.0, "total due": 3.5, "balance": 2.5,
        "salary": 3.0, "remittance": 3.5, "tax": 2.5, "payroll": 3.5, "statement": 2.5,
        "vat": 2.5, "subtotal": 3.0, "billing": 2.5, "amount paid": 3.0, "receipt": 3.0,
        "revenue": 2.5, "credit card": 3.5, "transaction": 2.5,
    },
    "legal_contracts": {
        "contract": 3.5, "agreement": 3.0, "party": 2.0, "hereto": 3.5, "jurisdiction": 3.0,
        "confidentiality": 3.0, "indemnification": 4.0, "breach": 2.5, "governing law": 4.0,
        "clause": 2.5, "nda": 4.0, "subpoena": 4.5, "court": 3.0, "attorney": 3.0,
        "liability": 2.5, "arbitration": 3.5, "signatory": 3.0, "terms and conditions": 3.0,
        "warranties": 3.0, "litigation": 3.5,
    },
    "confidential_internal": {
        "confidential": 3.5, "strictly private": 4.5, "internal use only": 4.0,
        "proprietary": 3.5, "trade secret": 4.5, "restricted": 3.0, "do not disclose": 4.0,
        "classified": 4.0, "privileged": 3.5, "eyes only": 4.5, "non-disclosure": 3.5,
        "sensitive": 2.5, "board memo": 4.0, "executive committee": 3.5,
    },
    "source_code": {
        "function": 2.0, "select": 1.5, "insert into": 3.5, "database": 2.0, "import ": 2.5,
        "class ": 2.0, "def ": 2.5, "return ": 1.5, "var ": 1.5, "const ": 1.5,
        "#!/bin/": 4.0, "<?php": 4.5, "namespace": 2.0, "endpoint": 2.5, "stdout": 2.5,
        "stderr": 2.5, "exception": 2.0, "public static void": 4.0,
    },
}


class DocumentSemanticClassifier:
    """Classifies text and document payloads into forensic sensitivity categories."""

    @classmethod
    def classify_text(cls, text: str) -> Dict[str, Any]:
        if not text or len(text.strip()) < 10:
            return {
                "top_topic": "general",
                "confidence": 0.0,
                "scores": {},
                "matched_terms": [],
            }

        text_lower = text.lower()
        scores: Dict[str, float] = {}
        matched_terms: List[str] = []

        for category, kw_dict in DOCUMENT_TOPIC_KEYWORDS.items():
            cat_score = 0.0
            for term, weight in kw_dict.items():
                if term in text_lower:
                    # Count occurrences up to a cap
                    count = min(5, text_lower.count(term))
                    cat_score += weight * (1.0 + 0.3 * (count - 1))
                    matched_terms.append(term)
            scores[category] = cat_score

        # Normalize with softmax-like scaling
        total_score = sum(scores.values())
        if total_score <= 1.0:
            return {
                "top_topic": "general",
                "confidence": 0.2,
                "scores": scores,
                "matched_terms": matched_terms[:10],
            }

        top_topic = max(scores, key=scores.get)
        confidence = round(min(0.98, scores[top_topic] / (total_score + 2.0)), 2)

        return {
            "top_topic": top_topic,
            "confidence": confidence,
            "scores": {k: round(v, 2) for k, v in scores.items()},
            "matched_terms": list(set(matched_terms))[:10],
        }



SUSPICIOUS_APIS = {
    "process_injection": [
        b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
        b"NtUnmapViewOfSection", b"QueueUserAPC", b"SetThreadContext",
        b"RtlMoveMemory",
    ],
    "keylogging_spyware": [
        b"GetAsyncKeyState", b"GetKeyState", b"SetWindowsHookExA",
        b"SetWindowsHookExW", b"GetClipboardData", b"BitBlt",
    ],
    "defense_evasion": [
        b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent", b"OutputDebugStringA",
        b"VirtualProtect", b"VirtualProtectEx", b"NtQueryInformationProcess",
    ],
    "persistence": [
        b"RegSetValueExA", b"RegSetValueExW", b"CreateServiceA",
        b"CreateServiceW", b"RunOnce",
    ],
    "network_c2": [
        b"InternetOpenA", b"InternetOpenW", b"URLDownloadToFileA",
        b"URLDownloadToFileW", b"HttpSendRequestA", b"WSAStartup",
    ],
}

KNOWN_PACKER_SECTIONS = [
    b"UPX0", b"UPX1", b"UPX2", b".aspack", b".vmp0", b".vmp1", b".themida",
    b"PECompact2", b".petite", b".fsg", b".nsp", b"FSG!",
]


class ExecutableRiskClassifier:

    @classmethod
    def analyze(cls, data: bytes) -> Dict[str, Any]:
        if not data.startswith(b"MZ") or len(data) < 512:
            return {
                "is_executable": False,
                "risk_score": 0.0,
                "packer": None,
                "capabilities": [],
                "high_entropy": False,
                "reasons": [],
            }

        reasons = []
        capabilities = []
        packer = None
        risk = 0.15  # Baseline risk for executable

        # 1. Packer section check
        for p_sec in KNOWN_PACKER_SECTIONS:
            if p_sec in data[:4096]:
                packer = p_sec.decode("ascii", errors="ignore").strip(".")
                risk += 0.40
                reasons.append(f"Packed with {packer}")
                break

        # 2. Section entropy check (first 64KB code segment)
        code_segment = data[512 : min(len(data), 65536)]
        if code_segment:
            freq = [0] * 256
            for b in code_segment:
                freq[b] += 1
            n = len(code_segment)
            entropy = -sum((c / n) * math.log2(c / n) for c in freq if c > 0)
            if entropy >= 7.2:
                risk += 0.30
                reasons.append(f"High code entropy ({entropy:.2f}/8.0 - packed/encrypted)")
            elif entropy >= 6.8:
                risk += 0.15
                reasons.append(f"Elevated code entropy ({entropy:.2f}/8.0)")

        # 3. Suspicious API scanning
        for cap_group, apis in SUSPICIOUS_APIS.items():
            found_apis = [api.decode("ascii", errors="ignore") for api in apis if api in data]
            if found_apis:
                capabilities.append(cap_group)
                if cap_group == "process_injection":
                    risk += 0.35
                    reasons.append(f"Injection APIs detected ({', '.join(found_apis[:2])})")
                elif cap_group == "keylogging_spyware":
                    risk += 0.25
                    reasons.append(f"Keylogging/Spyware APIs ({', '.join(found_apis[:2])})")
                elif cap_group == "defense_evasion":
                    risk += 0.20
                    reasons.append(f"Anti-Analysis APIs ({', '.join(found_apis[:2])})")
                elif cap_group in ("persistence", "network_c2"):
                    risk += 0.15
                    reasons.append(f"Persistence/C2 APIs ({', '.join(found_apis[:2])})")

        risk_score = round(min(1.0, risk), 2)
        return {
            "is_executable": True,
            "risk_score": risk_score,
            "packer": packer,
            "capabilities": capabilities,
            "high_entropy": "High code entropy" in str(reasons),
            "reasons": reasons,
        }


class VisionContentClassifier:

    @classmethod
    def analyze(cls, img_data: bytes) -> Dict[str, Any]:
        if not PIL_AVAILABLE or not img_data or len(img_data) < 64:
            return {"category": "unknown", "confidence": 0.0, "traits": []}

        try:
            bio = io.BytesIO(img_data)
            img = Image.open(bio)
            w, h = img.size
            mode = img.mode

            # Convert to RGB thumbnail
            thumb = img.convert("RGB").resize((96, 96), Image.Resampling.BOX if hasattr(Image, "Resampling") else Image.NEAREST)
            pixels = list(thumb.get_flattened_data()) if hasattr(thumb, "get_flattened_data") else list(thumb.getdata())

            traits = []
            category = "camera_photo"
            confidence = 0.65

            # 1. Luminance & Background Whitespace
            luminances = [(0.299 * r + 0.587 * g + 0.114 * b) for r, g, b in pixels]
            avg_lum = sum(luminances) / len(luminances)
            white_pixels = sum(1 for lum in luminances if lum > 220)
            white_ratio = white_pixels / len(luminances)

            # 2. Color Diversity & Saturation
            saturations = []
            for r, g, b in pixels:
                max_c = max(r, g, b)
                min_c = min(r, g, b)
                sat = (max_c - min_c) / max_c if max_c > 0 else 0
                saturations.append(sat)
            avg_sat = sum(saturations) / len(saturations)
            unique_colors = len(set(pixels))

            orthogonal_edges = 0
            for y in range(1, 95):
                for x in range(1, 95):
                    c = luminances[y * 96 + x]
                    right = luminances[y * 96 + x + 1]
                    down = luminances[(y + 1) * 96 + x]
                    if abs(c - right) > 40 or abs(c - down) > 40:
                        orthogonal_edges += 1
            edge_ratio = orthogonal_edges / (94 * 94)
            lsb_bits = [r & 1 for r, g, b in pixels[:1000]]
            ones = sum(lsb_bits)
            p1 = ones / len(lsb_bits) if lsb_bits else 0.5
            p0 = 1.0 - p1
            lsb_entropy = -(p0 * math.log2(p0) + p1 * math.log2(p1)) if (0 < p0 < 1 and 0 < p1 < 1) else 0.0

            if lsb_entropy > 0.995 and len(img_data) > 200 * 1024:
                traits.append("Uniform LSB entropy (Possible Steganography)")
            if white_ratio > 0.45 and avg_sat < 0.20:
                category = "document_scan"
                confidence = 0.90
                traits.append("High contrast white page with text lines")
            elif edge_ratio > 0.18 and unique_colors < 1500:
                category = "screenshot"
                confidence = 0.85
                traits.append("Rectilinear UI edges & interface palette")
            elif unique_colors < 250:
                category = "graphic_icon"
                confidence = 0.80
                traits.append("Low color count / Vector logo")
            else:
                category = "camera_photo"
                confidence = 0.75
                traits.append("Natural continuous color gradients")

            return {
                "category": category,
                "confidence": confidence,
                "traits": traits,
                "dimensions": f"{w}x{h}",
                "white_ratio": round(white_ratio, 2),
                "edge_density": round(edge_ratio, 3),
            }
        except Exception:
            return {"category": "unknown", "confidence": 0.0, "traits": []}



@dataclass
class ThreatEvaluation:
    threat_score: int          
    priority: str              
    risk_label: str            
    primary_category: str
    reasons: List[str]
    ai_confidence: float
    doc_topic: Optional[str] = None
    vision_category: Optional[str] = None
    binary_details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_score": self.threat_score,
            "priority": self.priority,
            "risk_label": self.risk_label,
            "primary_category": self.primary_category,
            "reasons": self.reasons,
            "ai_confidence": self.ai_confidence,
            "doc_topic": self.doc_topic,
            "vision_category": self.vision_category,
            "binary_details": self.binary_details,
        }


class MLTriageEngine:

    @classmethod
    def evaluate(
        cls,
        category: str,
        extension: str,
        data: bytes,
        yara_matches: Optional[List[Any]] = None,
        entropy_val: float = 0.0,
        is_encrypted: bool = False,
        is_fragmented: bool = False,
        file_confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ThreatEvaluation:
        score = 10
        reasons: List[str] = []
        doc_topic = None
        vision_category = None
        binary_details = None
        risk_label = "Benign Asset"
        ai_conf = 0.70

        if yara_matches:
            score += 45
            reasons.append(f"Matched {len(yara_matches)} YARA malware/threat rule(s)")
            risk_label = "YARA Threat Match"

        if category == "executable" or extension in ("exe", "dll", "sys", "elf", "scr"):
            bin_res = ExecutableRiskClassifier.analyze(data)
            binary_details = bin_res
            if bin_res["is_executable"]:
                bin_risk = bin_res["risk_score"]
                score += int(bin_risk * 50)
                reasons.extend(bin_res["reasons"])
                ai_conf = max(ai_conf, 0.85)
                if bin_res["packer"]:
                    risk_label = f"Packed Executable ({bin_res['packer']})"
                elif bin_risk >= 0.60:
                    risk_label = "Suspicious Executable"

        elif category in ("document", "email") or extension in ("txt", "pdf", "docx", "eml", "html", "json", "csv"):
            sample_text = ""
            try:
                clean = "".join(chr(b) if (32 <= b < 127 or b in (10, 13)) else " " for b in data[:65536])
                sample_text = clean
            except Exception:
                pass

            if sample_text:
                doc_res = DocumentSemanticClassifier.classify_text(sample_text)
                doc_topic = doc_res["top_topic"]
                if doc_topic != "general":
                    ai_conf = max(ai_conf, doc_res["confidence"])
                    matched_str = f" ({', '.join(doc_res['matched_terms'][:3])})" if doc_res["matched_terms"] else ""

                    if doc_topic == "credentials":
                        score += 65
                        risk_label = "Leaked Credentials / Secrets"
                        reasons.append(f"Detected authentication tokens or private keys{matched_str}")
                    elif doc_topic == "financial":
                        score += 45
                        risk_label = "Financial Document"
                        reasons.append(f"Identified financial/banking terminology{matched_str}")
                    elif doc_topic == "confidential_internal":
                        score += 42
                        risk_label = "Confidential / Trade Secret"
                        reasons.append(f"Marked as confidential/restricted memo{matched_str}")
                    elif doc_topic == "legal_contracts":
                        score += 30
                        risk_label = "Legal Contract"
                        reasons.append(f"Legal contract / litigation terms{matched_str}")
                    elif doc_topic == "source_code":
                        score += 25
                        risk_label = "Source Code / SQL"
                        reasons.append(f"Contains programming scripts/database queries{matched_str}")

        elif category == "image" or extension in ("jpg", "jpeg", "png", "bmp", "webp", "gif"):
            vis_res = VisionContentClassifier.analyze(data)
            vision_category = vis_res["category"]
            reasons.extend(vis_res["traits"])
            if vision_category == "document_scan":
                score += 30
                risk_label = "Scanned Paper Document"
            elif vision_category == "screenshot":
                score += 25
                risk_label = "UI Screenshot"
            if "Possible Steganography" in str(vis_res["traits"]):
                score += 40
                risk_label = "Steganography Suspect"

        if is_encrypted or entropy_val >= 7.2:
            score += 20
            reasons.append(f"High entropy ({entropy_val:.2f}) indicates strong encryption/packing")
            if risk_label == "Benign Asset":
                risk_label = "Encrypted Container / Data"

        if is_fragmented:
            score += 10
            reasons.append("Fragmented file carving")
        if file_confidence < 0.60:
            score += 10
            reasons.append("Low signature confidence requires analyst review")

        threat_score = min(100, max(5, score))

        if threat_score >= 80:
            priority = "critical"
        elif threat_score >= 60:
            priority = "high"
        elif threat_score >= 35:
            priority = "medium"
        else:
            priority = "low"

        if not reasons:
            reasons.append("Standard benign file with normal characteristics")

        return ThreatEvaluation(
            threat_score=threat_score,
            priority=priority,
            risk_label=risk_label,
            primary_category=category,
            reasons=reasons,
            ai_confidence=ai_conf,
            doc_topic=doc_topic,
            vision_category=vision_category,
            binary_details=binary_details,
        )
