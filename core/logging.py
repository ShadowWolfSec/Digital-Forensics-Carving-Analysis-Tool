from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional


LOG_DIR = Path(__file__).parent.parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "forensics_tool.log"
LOG_FILE_DEBUG = LOG_DIR / "forensics_tool_debug.log"



class ColoredFormatter(logging.Formatter):
    """Colored console output for better readability."""
    
    GREY = "\033[90m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    
    COLORS = {
        logging.DEBUG: GREY,
        logging.INFO: GREEN,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: RED + BOLD,
    }
    
    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


# Console formatter (simpler, colored)
CONSOLE_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
CONSOLE_DATE_FORMAT = "%H:%M:%S"

# File formatter (detailed, no colors)
FILE_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(filename)s:%(lineno)d | %(message)s"
FILE_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"



def setup_logging(
    level: int = logging.INFO,
    debug_file: bool = False,
    console: bool = True,
    log_file: Optional[Path] = None,
) -> logging.Logger:
    """
    Configure logging for the forensics tool.
    
    Args:
        level: Minimum log level (default: INFO)
        debug_file: Enable debug file logging (default: False)
        console: Enable console output (default: True)
        log_file: Custom log file path (default: logs/forensics_tool.log)
    
    Returns:
        Root logger instance
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  
    
    root_logger.handlers.clear()
    
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        
        # Use colored formatter if terminal supports it
        if sys.stdout.isatty():
            console_formatter = ColoredFormatter(
                CONSOLE_FORMAT, datefmt=CONSOLE_DATE_FORMAT
            )
        else:
            console_formatter = logging.Formatter(
                CONSOLE_FORMAT, datefmt=CONSOLE_DATE_FORMAT
            )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
    
    file_path = log_file or LOG_FILE
    file_handler = logging.FileHandler(file_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter(FILE_FORMAT, datefmt=FILE_DATE_FORMAT)
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    
    if debug_file:
        debug_handler = logging.FileHandler(LOG_FILE_DEBUG, encoding="utf-8")
        debug_handler.setLevel(logging.DEBUG)
        debug_formatter = logging.Formatter(FILE_FORMAT, datefmt=FILE_DATE_FORMAT)
        debug_handler.setFormatter(debug_formatter)
        root_logger.addHandler(debug_handler)
    
    # Log startup
    logger = logging.getLogger(__name__)
    logger.info(f"Logging initialized - Level: {logging.getLevelName(level)}")
    logger.info(f"Log file: {file_path}")
    if debug_file:
        logger.info(f"Debug log file: {LOG_FILE_DEBUG}")
    
    return root_logger



def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a module.
    
    Args:
        name: Module name (typically __name__)
    
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def set_level(level: int) -> None:
    """
    Change the logging level at runtime.
    
    Args:
        level: New log level (e.g., logging.DEBUG, logging.INFO)
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    for handler in root_logger.handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
            handler.setLevel(level)
    
    logging.getLogger(__name__).info(f"Log level changed to: {logging.getLevelName(level)}")


# ─────────────────────────────────────────────
#  Auto-initialize on import (optional)
# ─────────────────────────────────────────────

# Uncomment to auto-initialize on import:
# setup_logging()