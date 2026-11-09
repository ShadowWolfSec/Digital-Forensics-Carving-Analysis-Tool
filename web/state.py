from __future__ import annotations

import io
import json
import logging
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.models import HashBundle
from core.regex_searcher import RegexRawSearcher, PatternMatch
from core.mft_parser import MFTParser, MFTRecord
from core.image_readers import reader_for_source
from sdk import ForensicsCarver, SDKOptions

logger = logging.getLogger("web.state")


_STATE: Dict[str, Any] = {
    "last_result": None,
    "last_triage": [],
    "last_timeline": [],
}

_SCAN_LOCK = threading.Lock()
_SCAN_STOP_FLAG: List[bool] = [False]
_SCAN_THREAD: Optional[threading.Thread] = None
_SCAN_STATE: Dict[str, Any] = {
    "status": "idle",  
    "current_bytes": 0,
    "total_bytes": 0,
    "percent": 0.0,
    "files_found": 0,
    "start_time": 0.0,
    "elapsed_seconds": 0.0,
    "elapsed_str": "00:00:00",
    "speed_mb_s": 0.0,
    "eta_seconds": 0.0,
    "eta_str": "--:--:--",
    "total_time_str": "--:--:--",
    "source_path": "",
    "error": None,
}

# ── Export State & Locks ─────────────────────
_EXPORT_LOCK = threading.Lock()
_EXPORT_STOP_FLAG: List[bool] = [False]
_EXPORT_THREAD: Optional[threading.Thread] = None
_EXPORT_STATE: Dict[str, Any] = {
    "status": "idle",  
    "total_files": 0,
    "exported_files": 0,
    "current_file": "",
    "percent": 0.0,
    "start_time": 0.0,
    "elapsed_seconds": 0.0,
    "elapsed_str": "00:00:00",
    "speed_mb_s": 0.0,
    "eta_seconds": 0.0,
    "eta_str": "--:--:--",
    "bytes_written": 0,
    "total_bytes": 0,
    "target_dir": "",
    "error": None,
}

# ── Pattern Search State & Locks ─────────────
_SEARCH_LOCK = threading.Lock()
_SEARCH_STOP_FLAG: List[bool] = [False]
_SEARCH_THREAD: Optional[threading.Thread] = None
_SEARCH_STATE: Dict[str, Any] = {
    "status": "idle",  
    "current_bytes": 0,
    "total_bytes": 0,
    "percent": 0.0,
    "hits_count": 0,
    "start_time": 0.0,
    "elapsed_seconds": 0.0,
    "elapsed_str": "00:00:00",
    "speed_mb_s": 0.0,
    "eta_seconds": 0.0,
    "eta_str": "--:--:--",
    "source_path": "",
    "error": None,
}
_SEARCH_RESULTS: List[Dict[str, Any]] = []

# ── MFT Explorer State & Locks ───────────────
_MFT_LOCK = threading.Lock()
_MFT_STOP_FLAG: List[bool] = [False]
_MFT_THREAD: Optional[threading.Thread] = None
_MFT_STATE: Dict[str, Any] = {
    "status": "idle",  
    "current_bytes": 0,
    "total_bytes": 0,
    "percent": 0.0,
    "records_found": 0,
    "deleted_count": 0,
    "start_time": 0.0,
    "elapsed_seconds": 0.0,
    "elapsed_str": "00:00:00",
    "speed_mb_s": 0.0,
    "eta_seconds": 0.0,
    "eta_str": "--:--:--",
    "source_path": "",
    "error": None,
}
_MFT_RECORDS: List[MFTRecord] = []



def _format_duration(seconds: float) -> str:
    """Format duration into HH:MM:SS or MM:SS."""
    if seconds <= 0 or seconds != seconds or seconds == float("inf"):
        return "--:--:--"
    total_sec = int(round(seconds))
    hrs = total_sec // 3600
    mins = (total_sec % 3600) // 60
    secs = total_sec % 60
    if hrs > 0:
        return f"{hrs:02d}:{mins:02d}:{secs:02d}"
    return f"{mins:02d}:{secs:02d}"


def _bool(v: Any) -> bool:
    """Parse truthy string values."""
    return str(v).lower() in ("1", "true", "yes", "on")


def _get_carved_filename(cf: Any) -> str:
    """Generate canonical filename for carved asset."""
    ext = getattr(cf, "extension", "") or "bin"
    sig = getattr(cf, "signature", None)
    sig_id = getattr(sig, "id", "file") if sig else "file"
    cf_id = getattr(cf, "id", 0)
    start_offset = getattr(cf, "start_offset", 0)
    return f"file_{cf_id:04d}_{sig_id}_0x{start_offset:08X}.{ext}"


def _extract_carved_bytes(cf: Any, default_source: str = "") -> bytes:
    """Safely extract the binary payload of a carved file."""
    data = getattr(cf, "data", None)
    size = getattr(cf, "size", 0)
    if data is not None and len(data) == size:
        return data

    meta = getattr(cf, "metadata", {}) or {}
    source = meta.get("source_file") or default_source
    if not source:
        return data or b""

    clean_source = source.replace("/", "\\")
    is_device = clean_source.startswith("\\\\.\\")
    ext = Path(clean_source).suffix.lower() if not is_device else ""
    stype = "e01" if ext in (".e01", ".ex01") else ("aff" if ext in (".aff", ".afd", ".afm") else "file")
    reader = reader_for_source(source, stype)
    start_offset = getattr(cf, "start_offset", 0)
    try:
        with reader:
            return reader.read_at(start_offset, size)
    except Exception as e:
        logger.error(f"Error reading carved file #{getattr(cf, 'id', 0)} data: {e}")
        return data or b""


def _get_bytes_for_target(file_id: Optional[int], file_path: str) -> Tuple[Optional[bytes], str]:
    """Retrieve binary data and display name for a file_id or path."""
    if file_id is not None:
        result = _STATE["last_result"]
        if result:
            for cf in result.carved_files:
                if cf.id == file_id:
                    data = _extract_carved_bytes(cf, result.source_path)
                    name = f"#{cf.id} - {_get_carved_filename(cf)}"
                    return data, name
    if file_path:
        p = Path(file_path.strip())
        if p.exists() and p.is_file():
            try:
                data = p.read_bytes()
                return data, p.name
            except Exception:
                pass
    return None, ""




def _on_scan_progress(cur: int, total: int, files_cnt: int):
    with _SCAN_LOCK:
        if _SCAN_STATE["status"] not in ("running", "stopping"):
            return
        now = time.time()
        start = _SCAN_STATE["start_time"] or now
        elapsed = max(0.001, now - start)
        speed = cur / elapsed / (1024 * 1024)

        percent = 0.0
        eta = 0.0
        total_time = 0.0
        if total > 0:
            percent = min(100.0, (cur / total) * 100.0)
            remaining = max(0, total - cur)
            if speed > 0:
                eta = remaining / (speed * 1024 * 1024)
                total_time = elapsed + eta

        _SCAN_STATE["current_bytes"] = cur
        _SCAN_STATE["total_bytes"] = total
        _SCAN_STATE["percent"] = round(percent, 1)
        _SCAN_STATE["files_found"] = files_cnt
        _SCAN_STATE["elapsed_seconds"] = round(elapsed, 1)
        _SCAN_STATE["elapsed_str"] = _format_duration(elapsed)
        _SCAN_STATE["speed_mb_s"] = round(speed, 1)
        _SCAN_STATE["eta_seconds"] = round(eta, 1)
        _SCAN_STATE["eta_str"] = _format_duration(eta) if total > 0 else "Estimating..."
        _SCAN_STATE["total_time_str"] = _format_duration(total_time) if total > 0 else "--:--:--"


def _run_scan_thread(
    carver: ForensicsCarver,
    source_path: str,
    source_type: str,
    max_bytes: Optional[int],
    start_offset: int,
    recover_fragments: bool,
    scan_mode: str,
    output_dir: str,
    recovered_dir: str = "",
):
    try:
        result = carver.scan(
            source_path=source_path,
            source_type=source_type,
            max_bytes=max_bytes,
            start_offset=start_offset,
            recover_fragments=recover_fragments,
            scan_mode=scan_mode,
            progress_cb=_on_scan_progress,
            stop_flag=_SCAN_STOP_FLAG,
        )
        _STATE["last_result"] = result

        triage = []
        try:
            triage = carver.triage_scan(result)
            _STATE["last_triage"] = triage
        except Exception as te:
            logger.exception(f"Triage error: {te}")
            _STATE["last_triage"] = []

        timeline = []
        try:
            timeline = carver.generate_timeline(result, str(Path("gui_timeline_latest.json").resolve()))
            _STATE["last_timeline"] = timeline
        except Exception as tle:
            logger.exception(f"Timeline error: {tle}")
            _STATE["last_timeline"] = []

        if output_dir:
            try:
                out = Path(output_dir)
                out.mkdir(parents=True, exist_ok=True)
                view = carver.view_result(result)
                view.generate_report(str(out / "report.json"), fmt="json")
                view.generate_report(str(out / "report.csv"), fmt="csv")
                view.generate_report(str(out / "report.html"), fmt="html")
                try:
                    view.generate_report(str(out / "report.pdf"), fmt="pdf")
                except Exception:
                    pass

                triage_payload = {"items": [t.to_dict() for t in triage]}
                (out / "triage.json").write_text(
                    json.dumps(triage_payload, indent=2, ensure_ascii=False, default=str),
                    encoding="utf-8",
                )
            except Exception as oe:
                logger.exception(f"Report export error: {oe}")

        if recovered_dir:
            try:
                exported_cnt = _export_all_recovered(
                    result.carved_files,
                    target_dir=recovered_dir,
                    default_source=source_path,
                )
                logger.info(f"Auto-extracted {exported_cnt} recovered files into {recovered_dir}")
            except Exception as e:
                logger.exception(f"Error auto-exporting recovered files: {e}")

        with _SCAN_LOCK:
            _SCAN_STATE["status"] = "stopped" if _SCAN_STOP_FLAG[0] else "completed"
            _SCAN_STATE["files_found"] = len(result.carved_files)
            _SCAN_STATE["current_bytes"] = result.bytes_scanned
            now = time.time()
            elapsed = max(0.001, now - (_SCAN_STATE["start_time"] or now))
            _SCAN_STATE["elapsed_str"] = _format_duration(elapsed)
            _SCAN_STATE["eta_str"] = "00:00"
            _SCAN_STATE["total_time_str"] = _format_duration(elapsed)
    except Exception as e:
        logger.exception(f"Background scan error: {e}")
        with _SCAN_LOCK:
            _SCAN_STATE["status"] = "error"
            _SCAN_STATE["error"] = str(e)


def _export_all_recovered(
    carved_files: List[Any],
    target_dir: str,
    default_source: str = "",
    organize_by_type: bool = False,
) -> int:
    return _run_export_thread(carved_files, target_dir, default_source, organize_by_type)


def _run_export_thread(
    carved_files: List[Any],
    target_dir: str,
    default_source: str = "",
    organize_by_type: bool = False,
) -> int:
    try:
        out_path = Path(target_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        manifest = []
        count = 0
        bytes_written = 0
        total_files = len(carved_files)
        total_bytes = sum(getattr(cf, "size", 0) for cf in carved_files)

        with _EXPORT_LOCK:
            _EXPORT_STOP_FLAG[0] = False
            _EXPORT_STATE["status"] = "running"
            _EXPORT_STATE["total_files"] = total_files
            _EXPORT_STATE["total_bytes"] = total_bytes
            _EXPORT_STATE["exported_files"] = 0
            _EXPORT_STATE["bytes_written"] = 0
            _EXPORT_STATE["current_file"] = ""
            _EXPORT_STATE["start_time"] = time.time()
            _EXPORT_STATE["target_dir"] = str(target_dir)
            _EXPORT_STATE["error"] = None

        for cf in carved_files:
            if _EXPORT_STOP_FLAG[0]:
                break

            fname = os.path.basename(_get_carved_filename(cf))
            raw_category = getattr(cf.signature, "category", "") or "other" if getattr(cf, "signature", None) else "other"
            category = re.sub(r"[^a-zA-Z0-9_\-]", "_", str(raw_category))

            if organize_by_type:
                dest_dir = out_path / category
                dest_dir.mkdir(parents=True, exist_ok=True)
            else:
                dest_dir = out_path

            file_dest = (dest_dir / fname).resolve()
            # Strict boundary check against path traversal
            try:
                file_dest.relative_to(out_path.resolve())
            except ValueError:
                continue

            with _EXPORT_LOCK:
                _EXPORT_STATE["current_file"] = fname

            data = _extract_carved_bytes(cf, default_source)
            if data:
                file_dest.write_bytes(data)
                count += 1
                bytes_written += len(data)

                hashes_dict = cf.hashes.to_dict() if getattr(cf, "hashes", None) else None
                manifest.append({
                    "id": getattr(cf, "id", 0),
                    "filename": fname,
                    "rel_path": str(file_dest.relative_to(out_path)),
                    "type": getattr(cf, "type_name", ""),
                    "category": category,
                    "extension": getattr(cf, "extension", ""),
                    "offset": getattr(cf, "start_offset", 0),
                    "size": getattr(cf, "size", 0),
                    "status": getattr(cf, "recovery_status", ""),
                    "confidence": getattr(cf, "confidence", 0.0),
                    "hashes": hashes_dict,
                })

            now = time.time()
            start = _EXPORT_STATE["start_time"] or now
            elapsed = max(0.001, now - start)
            speed = bytes_written / elapsed / (1024 * 1024)
            pct = round((count / total_files) * 100.0, 1) if total_files > 0 else 100.0

            eta = 0.0
            if total_bytes > 0 and speed > 0:
                rem_bytes = max(0, total_bytes - bytes_written)
                eta = rem_bytes / (speed * 1024 * 1024)

            with _EXPORT_LOCK:
                _EXPORT_STATE["exported_files"] = count
                _EXPORT_STATE["bytes_written"] = bytes_written
                _EXPORT_STATE["percent"] = pct
                _EXPORT_STATE["elapsed_seconds"] = round(elapsed, 1)
                _EXPORT_STATE["elapsed_str"] = _format_duration(elapsed)
                _EXPORT_STATE["speed_mb_s"] = round(speed, 1)
                _EXPORT_STATE["eta_seconds"] = round(eta, 1)
                _EXPORT_STATE["eta_str"] = _format_duration(eta) if eta > 0 else "00:00"

        try:
            manifest_file = out_path / "recovered_manifest.json"
            manifest_file.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
            from core.reporter import seal_report
            seal_report(manifest_file)
        except Exception:
            pass

        with _EXPORT_LOCK:
            _EXPORT_STATE["status"] = "stopped" if _EXPORT_STOP_FLAG[0] else "completed"
            _EXPORT_STATE["percent"] = 100.0 if not _EXPORT_STOP_FLAG[0] else _EXPORT_STATE["percent"]
            now = time.time()
            elapsed = max(0.001, now - (_EXPORT_STATE["start_time"] or now))
            _EXPORT_STATE["elapsed_str"] = _format_duration(elapsed)
            _EXPORT_STATE["eta_str"] = "00:00"

        return count
    except Exception as e:
        logger.exception(f"Export thread error: {e}")
        with _EXPORT_LOCK:
            _EXPORT_STATE["status"] = "error"
            _EXPORT_STATE["error"] = str(e)
        return 0


def _on_search_progress(cur: int, total: int, hits_cnt: int):
    with _SEARCH_LOCK:
        if _SEARCH_STATE["status"] not in ("running", "stopping"):
            return
        now = time.time()
        start = _SEARCH_STATE["start_time"] or now
        elapsed = max(0.001, now - start)
        speed = cur / elapsed / (1024 * 1024)

        pct = 0.0
        eta = 0.0
        if total > 0:
            pct = min(100.0, (cur / total) * 100.0)
            rem = max(0, total - cur)
            if speed > 0:
                eta = rem / (speed * 1024 * 1024)

        _SEARCH_STATE["current_bytes"] = cur
        _SEARCH_STATE["total_bytes"] = total
        _SEARCH_STATE["percent"] = round(pct, 1)
        _SEARCH_STATE["hits_count"] = hits_cnt
        _SEARCH_STATE["elapsed_seconds"] = round(elapsed, 1)
        _SEARCH_STATE["elapsed_str"] = _format_duration(elapsed)
        _SEARCH_STATE["speed_mb_s"] = round(speed, 1)
        _SEARCH_STATE["eta_seconds"] = round(eta, 1)
        _SEARCH_STATE["eta_str"] = _format_duration(eta) if total > 0 else "Estimating..."


def _run_search_thread(
    source_path: str,
    patterns: List[str],
    custom_regex: str,
    max_bytes: Optional[int],
    start_offset: int,
):
    global _SEARCH_RESULTS
    try:
        searcher = RegexRawSearcher()
        matches = searcher.search(
            source_path=source_path,
            enabled_patterns=patterns,
            custom_regex=custom_regex,
            max_bytes=max_bytes,
            start_offset=start_offset,
            progress_cb=_on_search_progress,
            stop_flag=_SEARCH_STOP_FLAG,
        )
        with _SEARCH_LOCK:
            _SEARCH_RESULTS = [m.to_dict() for m in matches]
            _SEARCH_STATE["status"] = "stopped" if _SEARCH_STOP_FLAG[0] else "completed"
            _SEARCH_STATE["percent"] = 100.0 if not _SEARCH_STOP_FLAG[0] else _SEARCH_STATE["percent"]
            _SEARCH_STATE["hits_count"] = len(_SEARCH_RESULTS)
            now = time.time()
            elapsed = max(0.001, now - (_SEARCH_STATE["start_time"] or now))
            _SEARCH_STATE["elapsed_str"] = _format_duration(elapsed)
            _SEARCH_STATE["eta_str"] = "00:00"
    except Exception as e:
        logger.exception(f"Background pattern search error: {e}")
        with _SEARCH_LOCK:
            _SEARCH_STATE["status"] = "error"
            _SEARCH_STATE["error"] = str(e)


def _on_mft_progress(cur: int, total: int, rec_cnt: int):
    with _MFT_LOCK:
        if _MFT_STATE["status"] not in ("running", "stopping"):
            return
        now = time.time()
        start = _MFT_STATE["start_time"] or now
        elapsed = max(0.001, now - start)
        speed = cur / elapsed / (1024 * 1024)

        pct = 0.0
        eta = 0.0
        if total > 0:
            pct = min(100.0, (cur / total) * 100.0)
            rem = max(0, total - cur)
            if speed > 0:
                eta = rem / (speed * 1024 * 1024)

        _MFT_STATE["current_bytes"] = cur
        _MFT_STATE["total_bytes"] = total
        _MFT_STATE["percent"] = round(pct, 1)
        _MFT_STATE["records_found"] = rec_cnt
        _MFT_STATE["elapsed_seconds"] = round(elapsed, 1)
        _MFT_STATE["elapsed_str"] = _format_duration(elapsed)
        _MFT_STATE["speed_mb_s"] = round(speed, 1)
        _MFT_STATE["eta_seconds"] = round(eta, 1)
        _MFT_STATE["eta_str"] = _format_duration(eta) if total > 0 else "Estimating..."


def _run_mft_thread(source_path: str, start_offset: int, max_bytes: Optional[int]):
    global _MFT_RECORDS
    try:
        records = MFTParser.scan_source(
            source_path=source_path,
            start_offset=start_offset,
            max_bytes=max_bytes,
            progress_cb=_on_mft_progress,
            stop_flag=_MFT_STOP_FLAG,
        )
        with _MFT_LOCK:
            _MFT_RECORDS = records
            _MFT_STATE["status"] = "stopped" if _MFT_STOP_FLAG[0] else "completed"
            _MFT_STATE["percent"] = 100.0 if not _MFT_STOP_FLAG[0] else _MFT_STATE["percent"]
            _MFT_STATE["records_found"] = len(records)
            _MFT_STATE["deleted_count"] = sum(1 for r in records if r.is_deleted)
            now = time.time()
            elapsed = max(0.001, now - (_MFT_STATE["start_time"] or now))
            _MFT_STATE["elapsed_str"] = _format_duration(elapsed)
            _MFT_STATE["eta_str"] = "00:00"
    except Exception as e:
        logger.exception(f"Background MFT scan error: {e}")
        with _MFT_LOCK:
            _MFT_STATE["status"] = "error"
            _MFT_STATE["error"] = str(e)
