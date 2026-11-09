from __future__ import annotations

import logging
import os
from flask import Blueprint, jsonify, request
from core.drive_detector import get_system_drives

logger = logging.getLogger("web.routes_system")
system_bp = Blueprint("system", __name__)


@system_bp.route("/api/drives")
def api_drives():
    drives = get_system_drives()
    return jsonify({"ok": True, "drives": drives})


@system_bp.route("/api/pick-path")
def api_pick_path():
    kind = request.args.get("kind", "file").strip().lower()
    title = request.args.get("title", "Select Path")
    initial = request.args.get("initial", "").strip()
    selected = ""

    if kind == "drive":
        drives = get_system_drives()
        first_drive = drives[0]["id"] if drives else (r"\\.\PhysicalDrive0" if os.name == "nt" else "/dev/sda")
        return jsonify({"ok": True, "path": first_drive, "drives": drives})

    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        if kind == "dir":
            selected = filedialog.askdirectory(
                title=title,
                initialdir=initial or os.getcwd(),
                mustexist=False,
            )
        else:
            selected = filedialog.askopenfilename(
                title=title,
                initialdir=initial or os.getcwd(),
            )
        root.destroy()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "path": selected or ""})
