"""Bounded file log handler.

Keeps the active .log file from growing unbounded on busy clusters
(20+ nodes can produce ~100 MB/h, see #345 / #348).
"""
import os
import time
from logging.handlers import TimedRotatingFileHandler


class CappedTimedFileHandler(TimedRotatingFileHandler):
    """TimedRotatingFileHandler that drops the rotated file instead of archiving.

    Use when only the most recent N hours of operational logs matter and you
    want a strict upper bound on disk use. Audit logs go through a separate
    pipeline (see utils/audit.py), this only affects /opt/PegaProx/logs/<cluster>.log.
    """

    def doRollover(self):
        if self.stream:
            self.stream.close()
            self.stream = None
        try:
            os.remove(self.baseFilename)
        except FileNotFoundError:
            pass
        # recompute next rollover (mirrors parent logic)
        current = int(time.time())
        new_at = self.computeRollover(current)
        while new_at <= current:
            new_at += self.interval
        self.rolloverAt = new_at
        if not self.delay:
            self.stream = self._open()
