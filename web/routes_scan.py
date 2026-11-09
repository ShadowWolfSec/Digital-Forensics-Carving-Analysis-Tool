from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from flask import Blueprint, jsonify, redirect, render_template, request, url_for

from sdk import ForensicsCarver, SDKOptions
from .state import (
    _STATE,
    _SCAN_LOCK,
    _SCAN_STATE,
    _SCAN_STOP_FLAG,
    _SCAN_THREAD,
    _run_scan_thread,
    _bool,
)

logger = logging.getLogger("web.routes_scan")
scan_bp = Blueprint("scan", __name__)


@scan_bp.route("/")
def index():
    return render_template(
        "index.html",
        form={},
        has_result=_STATE["last_result"] is not None,
    )


@scan_bp.route("/scan", methods=["POST"])
def run_scan():
    has_res = _STATE["last_result"] is not None
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json

    with _SCAN_LOCK:
        if _SCAN_STATE["status"] in ("running", "stopping"):
            if is_ajax:
                return jsonify({"ok": False, "error": "A scan is already in progress."}), 400
            return render_template("index.html", form=request.form, error="A scan is already in progress.", has_result=has_res), 400

    source_path = request.form.get("source_path", "").strip()
    if not source_path:
        if is_ajax:
            return jsonify({"ok": False, "error": "Source path is required."}), 400
        return render_template("index.html", form=request.form, error="Source path is required.", has_result=has_res), 400

    is_device = source_path.startswith("\\\\.\\") or source_path.startswith("//./") or source_path.startswith("/dev/")
    if not is_device and not Path(source_path).exists():
        if is_ajax:
            return jsonify({"ok": False, "error": f"Path does not exist: {source_path}"}), 400
        return render_template("index.html", form=request.form, error=f"Path does not exist: {source_path}", has_result=has_res), 400

    use_yara = _bool(request.form.get("use_yara", ""))
    use_plugins = _bool(request.form.get("use_plugins", ""))
    use_output = _bool(request.form.get("use_output", ""))
    use_recovered = _bool(request.form.get("use_recovered", ""))

    yara_rules = request.form.get("yara_rules", "").strip() if use_yara else ""
    plugins_dir = request.form.get("plugins_dir", "").strip() if use_plugins else ""
    output_dir = request.form.get("output_dir", "").strip() if use_output else ""
    recovered_dir = request.form.get("recovered_dir", "").strip() if use_recovered else ""

    if use_yara and not yara_rules:
        err = "فعّلت YARA لكن لم تحدد مسار القواعد."
        if is_ajax:
            return jsonify({"ok": False, "error": err}), 400
        return render_template("index.html", form=request.form, error=err, has_result=has_res), 400
    if use_plugins and not plugins_dir:
        err = "فعّلت Plugins لكن لم تحدد مسار المجلد."
        if is_ajax:
            return jsonify({"ok": False, "error": err}), 400
        return render_template("index.html", form=request.form, error=err, has_result=has_res), 400
    if use_output and not output_dir:
        err = "فعّلت Output لكن لم تحدد مسار الحفظ."
        if is_ajax:
            return jsonify({"ok": False, "error": err}), 400
        return render_template("index.html", form=request.form, error=err, has_result=has_res), 400
    if use_recovered and not recovered_dir:
        err = "فعّلت استخراج الملفات المستعادة لكن لم تحدد مسار مجلد الحفظ."
        if is_ajax:
            return jsonify({"ok": False, "error": err}), 400
        return render_template("index.html", form=request.form, error=err, has_result=has_res), 400

    options = SDKOptions(
        analyst=request.form.get("analyst", "gui_user"),
        compute_hashes=not _bool(request.form.get("no_hash", "")),
        compute_entropy=not _bool(request.form.get("no_entropy", "")),
        yara_rules_path=yara_rules,
        signature_db_path=request.form.get("signature_db", ":memory:").strip() or ":memory:",
    )
    carver = ForensicsCarver(options)

    if plugins_dir:
        carver.load_plugins(plugins_dir)

    max_mb = request.form.get("max_mb", "0").strip() or "0"
    start_mb = request.form.get("start_mb", "0").strip() or "0"
    max_bytes = int(max_mb) * 1024 * 1024 if int(max_mb) > 0 else None
    start_offset = int(start_mb) * 1024 * 1024

    scan_mode = request.form.get("scan_mode", "deep").strip() or "deep"
    source_type = request.form.get("source_type", "auto").strip() or "auto"
    recover_fragments = _bool(request.form.get("recover_fragments", ""))

    with _SCAN_LOCK:
        _SCAN_STOP_FLAG[0] = False
        _SCAN_STATE["status"] = "running"
        _SCAN_STATE["current_bytes"] = 0
        _SCAN_STATE["total_bytes"] = max_bytes or 0
        _SCAN_STATE["percent"] = 0.0
        _SCAN_STATE["files_found"] = 0
        _SCAN_STATE["start_time"] = time.time()
        _SCAN_STATE["elapsed_seconds"] = 0.0
        _SCAN_STATE["elapsed_str"] = "00:00:00"
        _SCAN_STATE["speed_mb_s"] = 0.0
        _SCAN_STATE["eta_seconds"] = 0.0
        _SCAN_STATE["eta_str"] = "--:--:--"
        _SCAN_STATE["total_time_str"] = "--:--:--"
        _SCAN_STATE["source_path"] = source_path
        _SCAN_STATE["error"] = None

    scan_thread = threading.Thread(
        target=_run_scan_thread,
        args=(
            carver,
            source_path,
            source_type,
            max_bytes,
            start_offset,
            recover_fragments,
            scan_mode,
            output_dir,
            recovered_dir,
        ),
        daemon=True,
    )
    scan_thread.start()

    if is_ajax:
        return jsonify({"ok": True, "status": "started"})

    return redirect("/?scanning=1")


@scan_bp.route("/api/scan/progress")
def api_scan_progress():
    with _SCAN_LOCK:
        return jsonify(_SCAN_STATE)


@scan_bp.route("/api/scan/stop", methods=["POST"])
def api_scan_stop():
    with _SCAN_LOCK:
        if _SCAN_STATE["status"] == "running":
            _SCAN_STOP_FLAG[0] = True
            _SCAN_STATE["status"] = "stopping"
            return jsonify({"ok": True, "status": "stopping"})
        return jsonify({"ok": False, "status": _SCAN_STATE["status"]})


@scan_bp.route("/results")
def results():
    result = _STATE["last_result"]
    if result is None:
        return redirect("/")
    return render_template(
        "results.html",
        summary=result.summary(),
        files=result.carved_files,
        triage=[t.to_dict() for t in _STATE["last_triage"]],
        timeline=[e.to_dict() for e in _STATE["last_timeline"][:200]],
    )
