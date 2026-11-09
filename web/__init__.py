from __future__ import annotations

import os
from pathlib import Path
from flask import Flask

from .state import (
    _STATE,
    _SCAN_STATE,
    _SCAN_LOCK,
    _SCAN_STOP_FLAG,
    _EXPORT_STATE,
    _EXPORT_LOCK,
    _SEARCH_STATE,
    _SEARCH_LOCK,
    _SEARCH_RESULTS,
    _MFT_STATE,
    _MFT_LOCK,
    _MFT_RECORDS,
)
from .routes_scan import scan_bp
from .routes_preview import preview_bp
from .routes_hex import hex_bp
from .routes_system import system_bp
from .routes_search import search_bp
from .routes_compare import compare_bp
from .routes_mft import mft_bp


def create_app(test_config: dict | None = None) -> Flask:
    """Create and configure the Flask Forensics Web Application."""
    base_dir = Path(__file__).resolve().parent.parent
    template_dir = base_dir / "templates"
    static_dir = base_dir / "static"

    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir),
    )
    app.config["SECRET_KEY"] = "forensics-gui-dev"

    if test_config:
        app.config.update(test_config)

    # Register modular Blueprints
    app.register_blueprint(scan_bp)
    app.register_blueprint(preview_bp)
    app.register_blueprint(hex_bp)
    app.register_blueprint(system_bp)
    app.register_blueprint(search_bp)
    app.register_blueprint(compare_bp)
    app.register_blueprint(mft_bp)

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self' data:; "
            "connect-src 'self';"
        )
        return response

    return app


__all__ = [
    "create_app",
    "_STATE",
    "_SCAN_STATE",
    "_SCAN_LOCK",
    "_SCAN_STOP_FLAG",
    "_EXPORT_STATE",
    "_EXPORT_LOCK",
    "_SEARCH_STATE",
    "_SEARCH_LOCK",
    "_SEARCH_RESULTS",
    "_MFT_STATE",
    "_MFT_LOCK",
    "_MFT_RECORDS",
]
