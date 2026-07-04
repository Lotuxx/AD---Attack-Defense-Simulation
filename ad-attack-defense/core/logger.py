"""
Framework logger — writes to logs/ and stdout.
"""

import logging
import os
from datetime import datetime


LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)


class FrameworkLogger:
    def __init__(self, name: str):
        self.name = name
        log_file = os.path.join(LOG_DIR, f"framework_{datetime.now():%Y%m%d}.log")

        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.DEBUG)

        if not self._logger.handlers:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s [%(name)s] %(levelname)s — %(message)s"
            ))
            self._logger.addHandler(fh)

    def info(self, msg):    self._logger.info(msg)
    def debug(self, msg):   self._logger.debug(msg)
    def warning(self, msg): self._logger.warning(msg)
    def error(self, msg):   self._logger.error(msg)
