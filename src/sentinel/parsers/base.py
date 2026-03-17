"""Abstract base for log parsers (Strategy pattern)."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any

from sentinel.core.enums import LogType


class LogParser(ABC):
    """Base class that every log-format parser must implement."""

    @property
    @abstractmethod
    def log_type(self) -> LogType:
        """The log type this parser handles."""

    @abstractmethod
    def detect(self, sample: str) -> bool:
        """Return True if *sample* looks like this parser's format."""

    @abstractmethod
    def parse(self, line: str) -> dict[str, Any]:
        """Parse a single log line into a structured dict.

        Must always include a ``raw`` key with the original line.
        """

    # ------------------------------------------------------------------
    # Shared helpers available to all concrete parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_match(pattern: re.Pattern[str], text: str) -> re.Match[str] | None:
        """Compile-once, match-once helper."""
        return pattern.match(text)

    @staticmethod
    def _fallback(line: str) -> dict[str, Any]:
        """Return a minimal dict when parsing fails."""
        return {"raw": line}
