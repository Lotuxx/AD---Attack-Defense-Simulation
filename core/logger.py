"""
Framework Logger
================
Centralised logging for all framework components.

Writes structured log entries to a daily rotating log file in the logs/
directory. Each component (CLI, Executor, Loader, etc.) creates its own
named logger instance for easy filtering.

Log format:
    2025-06-01 14:23:01 [Executor] INFO — Module loaded: blue_team.audit_passwords
"""

import logging
import os
from datetime import datetime

# ── Log directory setup ───────────────────────────────────────────────────────
# Resolve the logs/ directory relative to this file's location (core/ → project root → logs/)
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)  # Create logs/ directory if it doesn't exist


class FrameworkLogger:
    """
    Named logger wrapper for a specific framework component.

    Creates a file handler writing to logs/framework_YYYYMMDD.log.
    Each logger instance is named after the component using it
    (e.g. 'CLI', 'Executor', 'WazuhAPI') for easy log filtering.

    Args:
        name (str): Component name used as the logger's identifier.

    Usage:
        logger = FrameworkLogger("MyModule")
        logger.info("Module started")
        logger.error("Something went wrong")
    """

    def __init__(self, name: str):
        self.name = name

        # Daily log file — rotates automatically by date
        log_file = os.path.join(LOG_DIR, f"framework_{datetime.now():%Y%m%d}.log")

        # Get or create a named logger (Python's logging module caches by name)
        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.DEBUG)  # Capture all levels

        # Only add handler once to avoid duplicate log entries on re-instantiation
        if not self._logger.handlers:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s [%(name)s] %(levelname)s — %(message)s"
            ))
            self._logger.addHandler(fh)

    # ── Convenience wrappers ──────────────────────────────────────────────────

    def info(self, msg: str):
        """Log an informational message (normal operation)."""
        self._logger.info(msg)

    def debug(self, msg: str):
        """Log a debug message (verbose detail for troubleshooting)."""
        self._logger.debug(msg)

    def warning(self, msg: str):
        """Log a warning (non-fatal issue that should be noted)."""
        self._logger.warning(msg)

    def error(self, msg: str):
        """Log an error (operation failed, action required)."""
        self._logger.error(msg)
