"""Fallback parser for unrecognised log formats."""

from __future__ import annotations

from typing import Any

from sentinel.core.enums import LogType
from sentinel.parsers.base import LogParser


class GenericParser(LogParser):
    """Catch-all parser that always matches but only stores the raw line."""

    @property
    def log_type(self) -> LogType:
        return LogType.GENERIC

    def detect(self, sample: str) -> bool:
        # Always matches as last-resort
        return True

    def parse(self, line: str) -> dict[str, Any]:
        return {"raw": line}
