from __future__ import annotations

import io
import json
import logging
import threading
import time
from flask import Blueprint, jsonify, render_template, request, send_file

from .state import (
    _STATE,
    _SEARCH_LOCK,
    _SEARCH_STATE,
    _SEARCH_STOP_FLAG,
    _SEARCH_RESULTS,
    _run_search_thread,
)

logger = logging.getLogger("web.routes_search")
search_bp = Blueprint("search", __name__)


@search_bp.route("/search")
def search_page():
    default_source = request.args.get("source", "").strip()
    if not default_source and _STATE["last_result"]:
        default_source = _STATE["last_result"].source_path
    return render_template(
        "search.html",
        default_source=default_source,
        has_result=_STATE["last_result"] is not None,
    )


@search_bp.route("/api/search/start", methods=["POST"])
def api_search_start():
    data = request.get_json(silent=True) or request.form or {}
    source_path = data.get("source_path", "").strip()
    if not source_path:
        return jsonify({"ok": False, "error": "Source path is required."}), 400

    patterns = data.get("patterns", [])
    if isinstance(patterns, str):
        try:
            patterns = json.loads(patterns)
        except Exception:
            patterns = [p.strip() for p in patterns.split(",") if p.strip()]

    custom_regex = data.get("custom_regex", "").strip()

    max_bytes_raw = data.get("max_bytes")
    max_bytes = None
    if max_bytes_raw is not None and str(max_bytes_raw).strip() != "":
        try:
            max_bytes = int(max_bytes_raw)
            if max_bytes <= 0:
                max_bytes = None
        except ValueError:
            max_bytes = None

    start_offset_raw = data.get("start_offset", "0")
    start_offset = 0
    if start_offset_raw:
        try:
            start_offset = int(str(start_offset_raw), 0)
        except ValueError:
            start_offset = 0

    with _SEARCH_LOCK:
        if _SEARCH_STATE["status"] == "running":
            return jsonify({"ok": False, "error": "A pattern search is already running."}), 400

        _SEARCH_STOP_FLAG[0] = False
        _SEARCH_STATE["status"] = "running"
        _SEARCH_STATE["current_bytes"] = 0
        _SEARCH_STATE["total_bytes"] = 0
        _SEARCH_STATE["percent"] = 0.0
        _SEARCH_STATE["hits_count"] = 0
        _SEARCH_STATE["start_time"] = time.time()
        _SEARCH_STATE["elapsed_seconds"] = 0.0
        _SEARCH_STATE["elapsed_str"] = "00:00:00"
        _SEARCH_STATE["speed_mb_s"] = 0.0
        _SEARCH_STATE["eta_seconds"] = 0.0
        _SEARCH_STATE["eta_str"] = "--:--:--"
        _SEARCH_STATE["source_path"] = source_path
        _SEARCH_STATE["error"] = None

    search_thread = threading.Thread(
        target=_run_search_thread,
        args=(source_path, patterns, custom_regex, max_bytes, start_offset),
        daemon=True,
    )
    search_thread.start()

    return jsonify({"ok": True, "status": "started", "source_path": source_path})


@search_bp.route("/api/search/progress")
def api_search_progress():
    with _SEARCH_LOCK:
        return jsonify(_SEARCH_STATE)


@search_bp.route("/api/search/stop", methods=["POST"])
def api_search_stop():
    with _SEARCH_LOCK:
        if _SEARCH_STATE["status"] == "running":
            _SEARCH_STOP_FLAG[0] = True
            _SEARCH_STATE["status"] = "stopping"
            return jsonify({"ok": True, "status": "stopping"})
        return jsonify({"ok": False, "status": _SEARCH_STATE["status"]})


@search_bp.route("/api/search/results")
def api_search_results():
    category = request.args.get("category", "").strip().lower()
    with _SEARCH_LOCK:
        import web.state as ws
        hits = list(ws._SEARCH_RESULTS)

    if category and category != "all":
        hits = [h for h in hits if h.get("category") == category]

    return jsonify({
        "ok": True,
        "count": len(hits),
        "total": len(ws._SEARCH_RESULTS),
        "results": hits,
    })


@search_bp.route("/api/search/export", methods=["GET", "POST"])
def api_search_export():
    fmt = request.args.get("fmt", "csv").lower()
    category = request.args.get("category", "all").lower()

    with _SEARCH_LOCK:
        import web.state as ws
        items = list(ws._SEARCH_RESULTS)

    if category != "all":
        items = [i for i in items if i.get("category") == category]

    if fmt == "json":
        data = json.dumps(items, indent=2, ensure_ascii=False)
        bio = io.BytesIO(data.encode("utf-8"))
        return send_file(
            bio,
            mimetype="application/json",
            as_attachment=True,
            download_name="pattern_search_results.json",
        )
    else:
        import csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Category", "Label", "Value", "Masked Value", "Offset Hex", "Offset Dec", "Source File", "Context Snippet"])
        for item in items:
            writer.writerow([
                item.get("id", ""),
                item.get("category", ""),
                item.get("label", ""),
                item.get("value", ""),
                item.get("masked_value", ""),
                item.get("offset_hex", ""),
                item.get("offset", ""),
                item.get("source_file", ""),
                item.get("context_text", "").replace("\n", " "),
            ])
        bio = io.BytesIO(output.getvalue().encode("utf-8-sig"))
        return send_file(
            bio,
            mimetype="text/csv",
            as_attachment=True,
            download_name="pattern_search_results.csv",
        )
