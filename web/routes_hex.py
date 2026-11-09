from __future__ import annotations

import logging
from pathlib import Path
from typing import List
from flask import Blueprint, jsonify, render_template, request

from core.image_readers import reader_for_source
from .state import _STATE

logger = logging.getLogger("web.routes_hex")
hex_bp = Blueprint("hex", __name__)


@hex_bp.route("/hex")
def hex_view():
    source = request.args.get("source", "").strip()
    offset = int(request.args.get("offset", "0"))
    if not source:
        result = _STATE["last_result"]
        if result:
            source = result.source_path

    is_device = source.startswith("\\\\.\\") or source.startswith("//./") or source.startswith("/dev/")
    if not source or (not is_device and not Path(source).exists()):
        return render_template("hex_viewer.html", error="Valid source file or drive path is required.", source=source)

    available_files: List[str] = []
    if not is_device and Path(source).is_dir():
        dir_path = Path(source)
        available_files = [str(p) for p in dir_path.rglob("*") if p.is_file()]
        if available_files:
            source = available_files[0]
        else:
            return render_template("hex_viewer.html", error=f"Directory contains no files to inspect: {dir_path}", source=str(dir_path))

    return render_template("hex_viewer.html", source=source, offset=offset, available_files=available_files)


@hex_bp.route("/api/hex")
def api_hex():
    source = request.args.get("source", "").strip()
    offset = int(request.args.get("offset", "0"))
    length = int(request.args.get("length", "256"))
    width = int(request.args.get("width", "16"))

    is_device = source.startswith("\\\\.\\") or source.startswith("//./") or source.startswith("/dev/")
    if not source or (not is_device and not Path(source).exists()):
        return jsonify({"error": "Source path not found"}), 400

    # If a directory path was sent directly, resolve to first file inside it
    if not is_device and Path(source).is_dir():
        files = [p for p in Path(source).rglob("*") if p.is_file()]
        if not files:
            return jsonify({"error": f"Directory has no readable files: {source}"}), 400
        source = str(files[0])

    if offset < 0:
        offset = 0
    length = max(16, min(length, 8192))
    width = max(8, min(width, 32))

    ext = Path(source).suffix.lower() if not is_device else ""
    stype = "e01" if ext in (".e01", ".ex01") else ("aff" if ext in (".aff", ".afd", ".afm") else "file")
    reader = reader_for_source(source, stype)
    try:
        with reader:
            data = reader.read_at(offset, length)
    except Exception as e:
        return jsonify({"error": f"Failed reading source: {e}"}), 500

    rows = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        rows.append({
            "offset": offset + i,
            "hex": " ".join(f"{b:02X}" for b in chunk),
            "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in chunk),
        })

    return jsonify({
        "source": source,
        "offset": offset,
        "length": len(data),
        "width": width,
        "rows": rows,
        "next_offset": offset + len(data),
        "prev_offset": max(0, offset - length),
    })
