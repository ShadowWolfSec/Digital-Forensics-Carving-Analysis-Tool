from __future__ import annotations
from core import FileSignature, ValidationResult
from core.plugins import ForensicsPlugin, PluginDefinition


def validate_acme(data: bytes) -> ValidationResult:
    if not data.startswith(b"ACME"):
        return ValidationResult(False, "Invalid ACME header", -0.5)
    version = data[4:8].decode("ascii", errors="replace")
    return ValidationResult(True, f"Valid ACME document (version {version})", 0.12)


def extract_acme_metadata(data: bytes):
    meta = {}
    if len(data) >= 16:
        meta["acme_version"] = data[4:8].decode("ascii", errors="replace")
        meta["marker"] = data[8:16].hex().upper()
    return meta


class Plugin(ForensicsPlugin):
    def definition(self) -> PluginDefinition:
        sig = FileSignature(
            id="acme_doc",
            name="ACME Document",
            description="Example custom plugin format",
            category="document",
            extensions=["acme"],
            mime_type="application/x-acme",
            header=b"ACME",
            trailer=None,
            max_file_size=25 * 1024 * 1024,
            validator="validate_generic",
            confidence=0.72,
        )
        return PluginDefinition(
            name="sample_acme_plugin",
            signature=sig,
            validator_name="validate_acme",
            validator_fn=validate_acme,
            metadata_extractor=extract_acme_metadata,
        )
