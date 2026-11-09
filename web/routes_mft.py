from __future__ import annotations

import io
import json
import logging
import os
import threading
import time
from flask import Blueprint, jsonify, render_template, request, send_file

from .state import (
    _STATE,
    _MFT_LOCK,
    _MFT_STATE,
    _MFT_STOP_FLAG,
    _MFT_RECORDS,
    _run_mft_thread,
)

logger = logging.getLogger("web.routes_mft")
mft_bp = Blueprint("mft", __name__)


@mft_bp.route("/mft")
def mft_page():
    default_source = request.args.get("source", "").strip()
    if not default_source and _STATE["last_result"]:
        default_source = _STATE["last_result"].source_path
    return render_template(
        "mft_explorer.html",
        default_source=default_source,
        has_result=_STATE["last_result"] is not None,
    )


@mft_bp.route("/api/mft/start", methods=["POST"])
def api_mft_start():
    data = request.get_json(silent=True) or request.form or {}
    source_path = data.get("source_path", "").strip()
    if not source_path:
        return jsonify({"ok": False, "error": "Source path is required."}), 400

    start_offset_raw = data.get("start_offset", "0")
    start_offset = 0
    if start_offset_raw:
        try:
            start_offset = int(str(start_offset_raw), 0)
        except ValueError:
            start_offset = 0

    max_bytes_raw = data.get("max_bytes")
    max_bytes = None
    if max_bytes_raw is not None and str(max_bytes_raw).strip() != "":
        try:
            max_bytes = int(max_bytes_raw)
            if max_bytes <= 0:
                max_bytes = None
        except ValueError:
            max_bytes = None

    with _MFT_LOCK:
        if _MFT_STATE["status"] == "running":
            return jsonify({"ok": False, "error": "An MFT scan is already in progress."}), 400

        _MFT_STOP_FLAG[0] = False
        _MFT_STATE["status"] = "running"
        _MFT_STATE["current_bytes"] = 0
        _MFT_STATE["total_bytes"] = 0
        _MFT_STATE["percent"] = 0.0
        _MFT_STATE["records_found"] = 0
        _MFT_STATE["deleted_count"] = 0
        _MFT_STATE["start_time"] = time.time()
        _MFT_STATE["elapsed_seconds"] = 0.0
        _MFT_STATE["elapsed_str"] = "00:00:00"
        _MFT_STATE["speed_mb_s"] = 0.0
        _MFT_STATE["eta_seconds"] = 0.0
        _MFT_STATE["eta_str"] = "--:--:--"
        _MFT_STATE["source_path"] = source_path
        _MFT_STATE["error"] = None

    mft_thread = threading.Thread(
        target=_run_mft_thread,
        args=(source_path, start_offset, max_bytes),
        daemon=True,
    )
    mft_thread.start()

    return jsonify({"ok": True, "status": "started", "source_path": source_path})


@mft_bp.route("/api/mft/progress")
def api_mft_progress():
    with _MFT_LOCK:
        return jsonify(_MFT_STATE)


@mft_bp.route("/api/mft/stop", methods=["POST"])
def api_mft_stop():
    with _MFT_LOCK:
        if _MFT_STATE["status"] == "running":
            _MFT_STOP_FLAG[0] = True
            _MFT_STATE["status"] = "stopping"
            return jsonify({"ok": True, "status": "stopping"})
        return jsonify({"ok": False, "status": _MFT_STATE["status"]})


@mft_bp.route("/api/mft/results")
def api_mft_results():
    filter_type = request.args.get("filter", "all").lower()
    with _MFT_LOCK:
        import web.state as ws
        records = list(ws._MFT_RECORDS)

    if filter_type == "deleted":
        records = [r for r in records if r.is_deleted]
    elif filter_type == "active":
        records = [r for r in records if not r.is_deleted]
    elif filter_type == "directory":
        records = [r for r in records if r.is_directory]
    elif filter_type == "resident":
        records = [r for r in records if r.resident_data and len(r.resident_data) > 0]

    return jsonify({
        "ok": True,
        "count": len(records),
        "total": len(ws._MFT_RECORDS),
        "records": [r.to_dict() for r in records],
    })


@mft_bp.route("/api/mft/extract/<int:rec_num>")
def api_mft_extract(rec_num: int):
    with _MFT_LOCK:
        import web.state as ws
        rec = next((r for r in ws._MFT_RECORDS if r.record_number == rec_num), None)

    if not rec or not rec.resident_data:
        return "No resident data payload available for this record.", 404

    fname = os.path.basename(rec.filename or f"record_{rec_num}.bin")
    return send_file(
        io.BytesIO(rec.resident_data),
        as_attachment=True,
        download_name=fname,
        mimetype="application/octet-stream",
    )


@mft_bp.route("/api/mft/export", methods=["GET", "POST"])
def api_mft_export():
    fmt = request.args.get("fmt", "csv").lower()
    filter_type = request.args.get("filter", "all").lower()

    with _MFT_LOCK:
        import web.state as ws
        records = list(ws._MFT_RECORDS)

    if filter_type == "deleted":
        records = [r for r in records if r.is_deleted]

    items = [r.to_dict() for r in records]

    if fmt == "json":
        data = json.dumps(items, indent=2, ensure_ascii=False)
        bio = io.BytesIO(data.encode("utf-8"))
        return send_file(
            bio,
            mimetype="application/json",
            as_attachment=True,
            download_name="mft_records.json",
        )
    else:
        import csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Record Number", "Status", "Type", "Filename", "Full Path", "Parent Record",
            "File Size", "Created Time (UTC)", "Modified Time (UTC)", "MFT Altered Time (UTC)",
            "Offset Hex", "Offset Dec", "Resident Data (Bytes)",
        ])
        for it in items:
            writer.writerow([
                it["record_number"],
                "DELETED" if it["is_deleted"] else "ACTIVE",
                "Directory" if it["is_directory"] else "File",
                it["filename"],
                it["full_path"],
                it["parent_record_number"],
                it["file_size"],
                it["created_time"] or "",
                it["modified_time"] or "",
                it["mft_altered_time"] or "",
                it["raw_offset_hex"],
                it["raw_offset"],
                it["resident_size"],
            ])
        bio = io.BytesIO(output.getvalue().encode("utf-8-sig"))
        return send_file(
            bio,
            mimetype="text/csv",
            as_attachment=True,
            download_name="mft_records.csv",
        )
