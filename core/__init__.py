"""forensics_tool.core — Digital Forensics Engine"""
from .logging import setup_logging, get_logger, set_level
from .models import (
    FileSignature, CarvedFile, ScanResult,
    EntropyResult, HashBundle, CustodyEntry, ValidationResult,
)
from .signatures import SignatureDatabase
from .engine import CarvingEngine
from .reporter import save_json, save_csv, save_html, save_jsonl, seal_report
from .timeline import TimelineAnalyzer, save_timeline_json
from .yara_engine import YaraScanner, YaraMatch
from .pdf_reporter import save_pdf, sign_pdf
from .plugins import ForensicsPlugin, PluginDefinition, PluginManager
from .ai_triage import AITriageEngine, TriageResult
from .custody import CustodyManager
from .source_detector import detect_source_type
from .metadata_extractors import extract_file_metadata, extract_basic_metadata

__all__ = [
    "setup_logging", "get_logger", "set_level",
    "FileSignature", "CarvedFile", "ScanResult",
    "EntropyResult", "HashBundle", "CustodyEntry", "ValidationResult",
    "SignatureDatabase", "CarvingEngine",
    "save_json", "save_csv", "save_html", "save_jsonl", "seal_report",
    "TimelineAnalyzer", "save_timeline_json",
    "YaraScanner", "YaraMatch",
    "save_pdf", "sign_pdf",
    "ForensicsPlugin", "PluginDefinition", "PluginManager",
    "AITriageEngine", "TriageResult",
    "CustodyManager", "detect_source_type",
    "extract_file_metadata", "extract_basic_metadata",
]
