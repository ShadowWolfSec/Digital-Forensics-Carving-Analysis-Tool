from __future__ import annotations

import io
import json
import logging
import threading
import time
from pathlib import Path
from flask import Blueprint, jsonify, request, send_file

from .state import (
    _STATE,
    _EXPORT_LOCK,
    _EXPORT_STATE,
    _EXPORT_STOP_FLAG,
    _get_carved_filename,
    _extract_carved_bytes,
    _run_export_thread,
)

logger = logging.getLogger("web.routes_preview")
preview_bp = Blueprint("preview", __name__)


@preview_bp.route("/api/download/<int:file_id>")
def api_download_file(file_id: int):
    result = _STATE["last_result"]
    if not result:
        return "No scan result available", 404

    target_cf = None
    for cf in result.carved_files:
        if cf.id == file_id:
            target_cf = cf
            break

    if not target_cf:
        return f"File #{file_id} not found in scan results", 404

    data = _extract_carved_bytes(target_cf, result.source_path)
    if not data:
        return "Could not read file data from source", 500

    filename = _get_carved_filename(target_cf)
    mime = target_cf.signature.mime_type if getattr(target_cf, "signature", None) else "application/octet-stream"

    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=filename,
        mimetype=mime,
    )


@preview_bp.route("/api/preview/<int:file_id>")
def api_preview_file(file_id: int):
    result = _STATE["last_result"]
    if not result:
        return "No scan result available", 404

    target_cf = None
    for cf in result.carved_files:
        if cf.id == file_id:
            target_cf = cf
            break

    if not target_cf:
        return f"File #{file_id} not found in scan results", 404

    data = _extract_carved_bytes(target_cf, result.source_path)
    if not data:
        return "Could not read file data from source", 500

    ext = getattr(target_cf, "extension", "").lower()
    mime = target_cf.signature.mime_type if getattr(target_cf, "signature", None) else "application/octet-stream"

    # Mime overrides for browser rendering
    if ext in ("jpg", "jpeg"):
        mime = "image/jpeg"
    elif ext == "png":
        mime = "image/png"
    elif ext == "gif":
        mime = "image/gif"
    elif ext == "webp":
        mime = "image/webp"
    elif ext == "bmp":
        mime = "image/bmp"
    elif ext == "pdf":
        mime = "application/pdf"
    elif ext in ("txt", "log", "csv", "json", "xml", "html", "yar", "sql", "bat"):
        mime = "text/plain; charset=utf-8"
    elif ext in ("mp4", "m4v"):
        mime = "video/mp4"
    elif ext in ("webm",):
        mime = "video/webm"
    elif ext in ("wav",):
        mime = "audio/wav"
    elif ext in ("mp3",):
        mime = "audio/mpeg"

    filename = _get_carved_filename(target_cf)

    return send_file(
        io.BytesIO(data),
        as_attachment=False,
        download_name=filename,
        mimetype=mime,
    )


@preview_bp.route("/api/preview-info/<int:file_id>")
def api_preview_info(file_id: int):
    result = _STATE["last_result"]
    if not result:
        return jsonify({"ok": False, "error": "No scan result available"}), 404

    target_cf = None
    for cf in result.carved_files:
        if cf.id == file_id:
            target_cf = cf
            break

    if not target_cf:
        return jsonify({"ok": False, "error": f"File #{file_id} not found"}), 404

    data = _extract_carved_bytes(target_cf, result.source_path)
    ext = getattr(target_cf, "extension", "").lower()
    cat = getattr(target_cf.signature, "category", "") or "other" if getattr(target_cf, "signature", None) else "other"

    text_content = ""
    is_text = ext in ("txt", "log", "csv", "json", "xml", "html", "yar", "sql", "bat")
    if is_text and data:
        for enc in ("utf-8", "utf-16", "cp1256", "latin-1"):
            try:
                text_content = data[:50000].decode(enc, errors="replace")
                break
            except Exception:
                continue

    # Hex snippet of first 256 bytes for binary preview
    hex_snippet = ""
    if data:
        head_bytes = data[: min(256, len(data))]
        hex_rows = []
        for i in range(0, len(head_bytes), 16):
            chunk = head_bytes[i : i + 16]
            h = " ".join(f"{b:02X}" for b in chunk)
            a = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            hex_rows.append(f"{i:04X}  {h:<48}  |{a}|")
        hex_snippet = "\n".join(hex_rows)

    return jsonify({
        "ok": True,
        "id": target_cf.id,
        "filename": _get_carved_filename(target_cf),
        "type": target_cf.type_name,
        "category": cat,
        "extension": ext,
        "size": target_cf.size,
        "start_offset": target_cf.start_offset,
        "end_offset": target_cf.end_offset,
        "status": target_cf.recovery_status,
        "confidence": round(target_cf.confidence, 4),
        "validation": target_cf.validation.message if getattr(target_cf, "validation", None) else "",
        "hashes": target_cf.hashes.to_dict() if getattr(target_cf, "hashes", None) else None,
        "entropy": target_cf.entropy.value if getattr(target_cf, "entropy", None) else None,
        "metadata": target_cf.metadata or {},
        "is_image": ext in ("jpg", "jpeg", "png", "gif", "webp", "bmp"),
        "is_pdf": ext == "pdf",
        "is_video": ext in ("mp4", "m4v", "webm", "wmv", "avi"),
        "is_audio": ext in ("mp3", "wav", "ogg", "flac"),
        "is_text": is_text,
        "text_content": text_content,
        "hex_snippet": hex_snippet,
    })


@preview_bp.route("/api/export/progress")
def api_export_progress():
    with _EXPORT_LOCK:
        return jsonify(_EXPORT_STATE)


@preview_bp.route("/api/export/stop", methods=["POST"])
def api_export_stop():
    with _EXPORT_LOCK:
        if _EXPORT_STATE["status"] == "running":
            _EXPORT_STOP_FLAG[0] = True
            _EXPORT_STATE["status"] = "stopping"
            return jsonify({"ok": True, "status": "stopping"})
        return jsonify({"ok": False, "status": _EXPORT_STATE["status"]})


@preview_bp.route("/api/export-all", methods=["POST"])
def api_export_all():
    result = _STATE["last_result"]
    if not result or not result.carved_files:
        return jsonify({"ok": False, "error": "No recovered files available to export."}), 400

    data = request.get_json(silent=True) or {}
    target_dir = data.get("target_dir", "").strip()
    file_ids = data.get("file_ids", [])
    organize = bool(data.get("organize_by_type", False))

    if not target_dir:
        # Open directory picker
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            target_dir = filedialog.askdirectory(title="Select Folder to Export Recovered Files")
            root.destroy()
        except Exception as e:
            return jsonify({"ok": False, "error": f"Failed opening folder picker: {e}"}), 500

    if not target_dir:
        return jsonify({"ok": False, "canceled": True, "error": "No directory selected."}), 200

    if file_ids and isinstance(file_ids, list):
        id_set = set(int(fid) for fid in file_ids if str(fid).isdigit())
        files_to_export = [cf for cf in result.carved_files if cf.id in id_set]
    else:
        files_to_export = result.carved_files

    if not files_to_export:
        return jsonify({"ok": False, "error": "No matching files selected for export."}), 400

    with _EXPORT_LOCK:
        if _EXPORT_STATE["status"] == "running":
            return jsonify({"ok": False, "error": "An export operation is already in progress."}), 400
        _EXPORT_STOP_FLAG[0] = False
        _EXPORT_STATE["status"] = "running"
        _EXPORT_STATE["total_files"] = len(files_to_export)
        _EXPORT_STATE["exported_files"] = 0
        _EXPORT_STATE["percent"] = 0.0
        _EXPORT_STATE["current_file"] = ""
        _EXPORT_STATE["start_time"] = time.time()
        _EXPORT_STATE["target_dir"] = str(target_dir)
        _EXPORT_STATE["error"] = None

    export_thread = threading.Thread(
        target=_run_export_thread,
        args=(files_to_export, target_dir, result.source_path, organize),
        daemon=True,
    )
    export_thread.start()

    return jsonify({
        "ok": True,
        "status": "started",
        "total_files": len(files_to_export),
        "target_dir": str(target_dir),
    })
