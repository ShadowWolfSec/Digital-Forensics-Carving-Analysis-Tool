from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# Ensure package directory is in sys.path
_pkg_dir = str(Path(__file__).resolve().parent)
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

from core import setup_logging
from web import (
    create_app,
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

logger = logging.getLogger("gui_app")

# Global Flask application instance (compatible with tests: `from gui_app import app`)
app = create_app()


def main():
    """Run local development server."""
    setup_logging(level=logging.INFO, console=True)
    port = int(os.environ.get("FORENSICS_GUI_PORT", "5000"))
    print(f"[*] Starting Digital Forensics Web GUI on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()