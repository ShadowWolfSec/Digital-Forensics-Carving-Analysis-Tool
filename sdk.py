"""
Public SDK facade for developers.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from core.ai_triage import AITriageEngine, TriageResult
from core.engine import CarvingEngine
from core.models import CarvedFile, ScanResult
from core.pdf_reporter import save_pdf, sign_pdf
from core.plugins import PluginManager
from core.reporter import save_csv, save_html, save_json, save_jsonl
from core.signatures import SignatureDatabase
from core.timeline import TimelineAnalyzer, save_timeline_json


@dataclass
class SDKOptions:
    analyst: str = "sdk_user"
    compute_hashes: bool = True
    compute_entropy: bool = True
    yara_rules_path: str = ""
    signature_db_path: str = ":memory:"


class ScanView:
    def __init__(self, result: ScanResult):
        self.result = result

    def filter(self, category: str = "", min_confidence: float = 0.0) -> List[CarvedFile]:
        items = self.result.carved_files
        if category:
            items = [f for f in items if f.signature.category == category]
        if min_confidence > 0:
            items = [f for f in items if f.confidence >= min_confidence]
        return items

    def generate_report(self, output_path: str, fmt: str = "json"):
        fmt = fmt.lower()
        if fmt == "json":
            save_json(self.result, output_path)
        elif fmt in ("jsonl", "ndjson"):
            save_jsonl(self.result, output_path)
        elif fmt == "csv":
            save_csv(self.result, output_path)
        elif fmt == "html":
            save_html(self.result, output_path)
        elif fmt == "pdf":
            save_pdf(self.result, output_path)
        else:
            raise ValueError(f"unsupported report format: {fmt}")


class ForensicsCarver:
    def __init__(self, options: Optional[SDKOptions] = None):
        self.options = options or SDKOptions()
        self.sig_db = SignatureDatabase(db_path=self.options.signature_db_path)
        self.plugins = PluginManager()
        self.triage = AITriageEngine()

    def load_plugins(self, plugins_dir: str) -> List[str]:
        names = self.plugins.load_from_dir(plugins_dir)
        self.plugins.apply_to_db(self.sig_db)
        return names

    def scan(
        self,
        source_path: str,
        source_type: str = "auto",
        max_bytes: Optional[int] = None,
        start_offset: int = 0,
        recover_fragments: bool = False,
        scan_mode: str = "deep",
        progress_cb: Optional[Callable[[int, int, int], None]] = None,
        stop_flag: Optional[List[bool]] = None,
    ) -> ScanResult:
        engine = CarvingEngine(
            sig_db=self.sig_db,
            analyst=self.options.analyst,
            compute_hashes=self.options.compute_hashes,
            compute_entropy=self.options.compute_entropy,
            yara_rules_path=self.options.yara_rules_path,
            progress_cb=progress_cb,
            stop_flag=stop_flag,
        )
        result = engine.scan(
            source_path=source_path,
            source_type=source_type,
            max_bytes=max_bytes,
            start_offset=start_offset,
            recover_fragments=recover_fragments,
            scan_mode=scan_mode,
        )
        return result

    def view_result(self, result: ScanResult) -> ScanView:
        return ScanView(result)

    def scan_view(self, *args, **kwargs) -> ScanView:
        return ScanView(self.scan(*args, **kwargs))

    def triage_scan(self, result: ScanResult) -> List[TriageResult]:
        source_path = getattr(result, "source_path", "")
        return self.triage.classify_many(result.carved_files, source_path=source_path)

    def generate_timeline(self, result: ScanResult, output_path: str):
        events = TimelineAnalyzer.build(result)
        save_timeline_json(events, output_path)
        return events

    def sign_pdf_report(
        self,
        result: ScanResult,
        output_pdf_path: str,
        cert_pem_path: str,
        key_pem_path: str,
        passphrase: str = "",
    ):
        unsigned = str(Path(output_pdf_path).with_suffix(".unsigned.pdf"))
        save_pdf(result, unsigned)
        sign_pdf(unsigned, output_pdf_path, cert_pem_path, key_pem_path, passphrase or None)

