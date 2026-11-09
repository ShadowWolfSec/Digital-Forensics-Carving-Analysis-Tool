from __future__ import annotations
import hashlib
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Tuple




@dataclass(slots=True)
class FileSignature:
    id: str
    name: str
    description: str
    category: str         
    extensions: List[str]
    mime_type: str
    header: bytes
    header_offset: int = 0
    trailer: Optional[bytes] = None
    trailer_offset: Optional[int] = None
    max_file_size: int = 100 * 1024 * 1024
    validator: str = "validate_generic"
    confidence: float = 0.9
    # ZIP-family resolution: inner paths that confirm sub-type
    zip_inner_paths: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"<FileSignature id={self.id!r} name={self.name!r}>"




@dataclass(slots=True)
class EntropyResult:
    value: float         
    classification: str   # 'plaintext' | 'compressed' | 'encrypted' | 'binary'
    is_encrypted: bool
    is_compressed: bool

    @classmethod
    def from_bytes(cls, data: bytes) -> "EntropyResult":
        if not data:
            return cls(0.0, "empty", False, False)
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        entropy = -sum((c / n) * math.log2(c / n) for c in freq if c)
        if entropy < 3.0:
            classification = "plaintext"
        elif entropy < 6.0:
            classification = "binary"
        elif entropy < 7.2:
            classification = "compressed"
        else:
            classification = "encrypted"
        return cls(
            value=round(entropy, 4),
            classification=classification,
            is_encrypted=entropy >= 7.2,
            is_compressed=6.0 <= entropy < 7.2,
        )



@dataclass(slots=True)
class HashBundle:
    md5: str
    sha1: str
    sha256: str
    ssdeep: str = ""

    @classmethod
    def from_bytes(cls, data: bytes) -> "HashBundle":
        ssdeep_val = ""
        try:
            from .fuzzy_hasher import FuzzyHasher
            ssdeep_val = FuzzyHasher.compute(data)
        except Exception:
            ssdeep_val = ""
        return cls(
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(),
            ssdeep=ssdeep_val,
        )

    def to_dict(self) -> Dict[str, str]:
        d = {"md5": self.md5, "sha1": self.sha1, "sha256": self.sha256}
        if self.ssdeep:
            d["ssdeep"] = self.ssdeep
        return d


def calculate_hashes_from_stream(read_fn, max_bytes: int = 50 * 1024 * 1024) -> Optional[HashBundle]:
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        pos = 0
        while pos < max_bytes:
            chunk = read_fn(min(64 * 1024, max_bytes - pos))
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            pos += len(chunk)
        return HashBundle(md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest())
    except Exception:
        return None




@dataclass(slots=True)
class CustodyEntry:
    timestamp: str
    action: str
    analyst: str
    details: str
    source_hash: str = ""

    @classmethod
    def now(cls, action: str, analyst: str, details: str, source_hash: str = "") -> "CustodyEntry":
        return cls(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            action=action,
            analyst=analyst,
            details=details,
            source_hash=source_hash,
        )

    def to_dict(self) -> Dict[str, str]:
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "analyst": self.analyst,
            "details": self.details,
            "source_hash": self.source_hash,
        }



@dataclass(slots=True)
class ValidationResult:
    is_valid: bool
    message: str
    confidence_boost: float = 0.0   



@dataclass(slots=True)
class CarvedFile:
    id: int
    signature: FileSignature
    start_offset: int
    end_offset: int
    size: int
    confidence: float
    header_hex: str
    trailer_hex: str
    recovery_status: str          
    validation: ValidationResult
    hashes: Optional[HashBundle] = None
    entropy: Optional[EntropyResult] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    blocks: List[Tuple[int, int]] = field(default_factory=list)
    # Raw data — populated only when recover=True
    data: Optional[bytes] = None
    is_embedded: bool = False
    artifact_type: str = "primary"  

    @property
    def type_name(self) -> str:
        return self.signature.name

    @property
    def extension(self) -> str:
        return self.signature.extensions[0] if self.signature.extensions else "bin"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type_name,
            "signature_id": self.signature.id,
            "category": self.signature.category,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "size": self.size,
            "size_human": _human_size(self.size),
            "confidence": round(self.confidence, 4),
            "header_hex": self.header_hex,
            "trailer_hex": self.trailer_hex,
            "recovery_status": self.recovery_status,
            "validation": self.validation.message,
            "hashes": self.hashes.to_dict() if self.hashes else None,
            "entropy": {
                "value": self.entropy.value,
                "classification": self.entropy.classification,
                "encrypted": self.entropy.is_encrypted,
            } if self.entropy else None,
            "metadata": self.metadata,
            "blocks": [{"start": s, "end": e} for s, e in self.blocks],
            "is_embedded": self.is_embedded,
            "artifact_type": self.artifact_type,
        }



@dataclass(slots=True)
class ScanResult:
    source_path: str
    source_type: str
    source_hash: Optional[HashBundle]
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    blocks_scanned: int = 0
    bytes_scanned: int = 0
    carved_files: List[CarvedFile] = field(default_factory=list)
    custody_log: List[CustodyEntry] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def files_found(self) -> int:
        return len(self.carved_files)

    @property
    def primary_files_count(self) -> int:
        return sum(1 for f in self.carved_files if not f.is_embedded)

    @property
    def embedded_artifacts_count(self) -> int:
        return sum(1 for f in self.carved_files if f.is_embedded)

    def summary(self) -> Dict[str, Any]:
        return {
            "source": self.source_path,
            "source_type": self.source_type,
            "source_hash": self.source_hash.to_dict() if self.source_hash else None,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": round(self.duration_seconds, 2),
            "blocks_scanned": self.blocks_scanned,
            "bytes_scanned": self.bytes_scanned,
            "bytes_scanned_human": _human_size(self.bytes_scanned),
            "files_found": self.files_found,
            "primary_files_count": self.primary_files_count,
            "embedded_artifacts_count": self.embedded_artifacts_count,
            "by_type": self._count_by_type(),
            "errors": self.errors,
        }

    def _count_by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.carved_files:
            counts[f.type_name] = counts.get(f.type_name, 0) + 1
        return counts


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
