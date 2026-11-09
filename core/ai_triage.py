from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import CarvedFile
from .ml_triage import MLTriageEngine, ThreatEvaluation


@dataclass
class TriageResult:
    file_id: int
    priority: str              
    risk: str                 
    category: str
    score: float              
    reasons: List[str]
    threat_score: int = 10    
    risk_label: str = "Benign Asset"
    ai_confidence: float = 0.70
    doc_topic: Optional[str] = None
    vision_category: Optional[str] = None
    binary_details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_id": self.file_id,
            "priority": self.priority,
            "risk": self.risk,
            "category": self.category,
            "score": round(self.score, 4),
            "threat_score": self.threat_score,
            "risk_label": self.risk_label,
            "ai_confidence": round(self.ai_confidence, 2),
            "doc_topic": self.doc_topic,
            "vision_category": self.vision_category,
            "binary_details": self.binary_details,
            "reasons": self.reasons,
        }


class AITriageEngine:

    def classify(self, cf: CarvedFile, data_bytes: Optional[bytes] = None) -> TriageResult:
        category = getattr(cf.signature, "category", "unknown") if getattr(cf, "signature", None) else "unknown"
        ext = getattr(cf, "extension", "").lower()
        entropy_val = getattr(cf.entropy, "value", 0.0) if getattr(cf, "entropy", None) else 0.0
        is_encrypted = getattr(cf.entropy, "is_encrypted", False) if getattr(cf, "entropy", None) else False
        is_frag = getattr(cf, "recovery_status", "") == "FRAGMENTED"
        confidence = getattr(cf, "confidence", 1.0)
        yara_matches = cf.metadata.get("yara_matches") if isinstance(getattr(cf, "metadata", None), dict) else None

        data = data_bytes or b""

        threat: ThreatEvaluation = MLTriageEngine.evaluate(
            category=category,
            extension=ext,
            data=data,
            yara_matches=yara_matches,
            entropy_val=entropy_val,
            is_encrypted=is_encrypted,
            is_fragmented=is_frag,
            file_confidence=confidence,
            metadata=getattr(cf, "metadata", {}),
        )

        return TriageResult(
            file_id=cf.id,
            priority=threat.priority,
            risk=threat.risk_label,
            category=category,
            score=round(threat.threat_score / 100.0, 4),
            threat_score=threat.threat_score,
            risk_label=threat.risk_label,
            ai_confidence=threat.ai_confidence,
            doc_topic=threat.doc_topic,
            vision_category=threat.vision_category,
            binary_details=threat.binary_details,
            reasons=threat.reasons,
        )

    def classify_many(self, files: List[CarvedFile], source_path: str = "") -> List[TriageResult]:
        reader = None
        current_reader_path = ""
        if source_path:
            try:
                from .source_reader import SourceReader
                reader = SourceReader(source_path)
                current_reader_path = source_path
            except Exception:
                reader = None

        results = []
        try:
            for f in files:
                data_sample = getattr(f, "data", None)
                if not data_sample:
                    f_src = source_path or (f.metadata.get("source_file") if isinstance(getattr(f, "metadata", None), dict) else "")
                    if f_src and f_src != current_reader_path:
                        if reader:
                            try:
                                reader.close()
                            except Exception:
                                pass
                        try:
                            from .source_reader import SourceReader
                            reader = SourceReader(f_src)
                            current_reader_path = f_src
                        except Exception:
                            reader = None
                    if reader and hasattr(f, "start_offset") and hasattr(f, "size"):
                        try:
                            read_len = min(getattr(f, "size", 65536), 65536)
                            data_sample = reader.read_at(f.start_offset, read_len)
                        except Exception:
                            pass
                results.append(self.classify(f, data_sample))
        finally:
            if reader:
                try:
                    reader.close()
                except Exception:
                    pass

        return results
