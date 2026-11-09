from __future__ import annotations

import logging
from flask import Blueprint, jsonify, render_template, request

from core.models import HashBundle
from core.fuzzy_hasher import FuzzyHasher
from core.perceptual_hasher import PerceptualHasher
from core.byte_differ import ByteDiffer
from .state import (
    _STATE,
    _get_carved_filename,
    _get_bytes_for_target,
)

logger = logging.getLogger("web.routes_compare")
compare_bp = Blueprint("compare", __name__)


@compare_bp.route("/compare")
def compare_page():
    result = _STATE["last_result"]
    carved_list = []
    if result and result.carved_files:
        for cf in result.carved_files:
            carved_list.append({
                "id": cf.id,
                "name": _get_carved_filename(cf),
                "type": getattr(cf, "type_name", ""),
                "size": getattr(cf, "size", 0),
                "extension": getattr(cf, "extension", ""),
            })
    file_a = request.args.get("a", "")
    file_b = request.args.get("b", "")
    return render_template(
        "compare.html",
        carved_files=carved_list,
        default_a=file_a,
        default_b=file_b,
        has_result=result is not None,
    )


@compare_bp.route("/api/compare", methods=["POST"])
def api_compare():
    data = request.get_json(silent=True) or request.form or {}

    id_a = data.get("id_a")
    if id_a is not None and str(id_a).isdigit():
        id_a = int(id_a)
    else:
        id_a = None
    path_a = data.get("path_a", "").strip()

    id_b = data.get("id_b")
    if id_b is not None and str(id_b).isdigit():
        id_b = int(id_b)
    else:
        id_b = None
    path_b = data.get("path_b", "").strip()

    bytes_a, name_a = _get_bytes_for_target(id_a, path_a)
    bytes_b, name_b = _get_bytes_for_target(id_b, path_b)

    if bytes_a is None:
        return jsonify({"ok": False, "error": "Could not read data for File A. Make sure ID or path is valid."}), 400
    if bytes_b is None:
        return jsonify({"ok": False, "error": "Could not read data for File B. Make sure ID or path is valid."}), 400

    # 1. Traditional Hashes
    hashes_a = HashBundle.from_bytes(bytes_a).to_dict()
    hashes_b = HashBundle.from_bytes(bytes_b).to_dict()
    hash_match = {
        "md5": hashes_a["md5"] == hashes_b["md5"],
        "sha1": hashes_a["sha1"] == hashes_b["sha1"],
        "sha256": hashes_a["sha256"] == hashes_b["sha256"],
    }

    # 2. Fuzzy Hashing (ssdeep / CTPH)
    fuzzy_a = hashes_a.get("ssdeep") or FuzzyHasher.compute(bytes_a)
    fuzzy_b = hashes_b.get("ssdeep") or FuzzyHasher.compute(bytes_b)
    fuzzy_score = FuzzyHasher.compare(fuzzy_a, fuzzy_b)

    fuzzy_verdict = (
        "100% Identical" if fuzzy_score == 100 else (
            f"{fuzzy_score}% Near-Identical / Minor Modification" if fuzzy_score >= 85 else (
                f"{fuzzy_score}% Likely Related / Malware Variant" if fuzzy_score >= 50 else (
                    f"{fuzzy_score}% Low Similarity / Divergent" if fuzzy_score > 0 else "0% Unrelated"
                )
            )
        )
    )

    # 3. Perceptual Image Hashing (if applicable)
    image_comparison = None
    if PerceptualHasher.is_available():
        try:
            img_res = PerceptualHasher.compare_images(bytes_a, bytes_b)
            if img_res.get("ok"):
                image_comparison = img_res
        except Exception:
            pass

    # 4. Byte Differ
    diff_res = ByteDiffer.diff(bytes_a, bytes_b)

    preview_url_a = f"/api/preview/{id_a}" if id_a is not None else None
    preview_url_b = f"/api/preview/{id_b}" if id_b is not None else None

    return jsonify({
        "ok": True,
        "file_a": {
            "name": name_a,
            "size": len(bytes_a),
            "hashes": hashes_a,
            "fuzzy": fuzzy_a,
            "preview_url": preview_url_a,
        },
        "file_b": {
            "name": name_b,
            "size": len(bytes_b),
            "hashes": hashes_b,
            "fuzzy": fuzzy_b,
            "preview_url": preview_url_b,
        },
        "hash_match": hash_match,
        "fuzzy_similarity": fuzzy_score,
        "fuzzy_verdict": fuzzy_verdict,
        "image_comparison": image_comparison,
        "byte_diff": diff_res,
    })
