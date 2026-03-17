"""Parser registry with auto-detection and log preprocessing."""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd

from sentinel.core.enums import LogType
from sentinel.parsers.base import LogParser
from sentinel.parsers.generic import GenericParser
from sentinel.parsers.hdfs import HDFSParser
from sentinel.parsers.openstack import OpenStackParser
from sentinel.parsers.syslog import SecurityLogParser, SyslogParser
from sentinel.parsers.web_server import WebServerParser

logger = logging.getLogger(__name__)

# Ordered from most specific to least specific. GenericParser is always last.
_DEFAULT_PARSERS: list[LogParser] = [
    SecurityLogParser(),
    WebServerParser(),
    HDFSParser(),
    OpenStackParser(),
    SyslogParser(),
    GenericParser(),
]


class ParserRegistry:
    """Registry that holds parsers and selects the right one for a log sample."""

    def __init__(self, parsers: list[LogParser] | None = None) -> None:
        self._parsers = parsers if parsers is not None else list(_DEFAULT_PARSERS)

    def register(self, parser: LogParser) -> None:
        """Add a parser to the registry (inserted before GenericParser)."""
        # Keep GenericParser last
        insert_idx = len(self._parsers) - 1 if self._parsers else 0
        self._parsers.insert(insert_idx, parser)

    def detect(self, sample: str) -> LogParser:
        """Return the first parser whose ``detect`` matches *sample*."""
        for parser in self._parsers:
            if parser.detect(sample):
                return parser
        # Should never happen because GenericParser always matches
        return GenericParser()

    def detect_type(self, sample: str) -> LogType:
        """Convenience: detect and return the log type enum."""
        return self.detect(sample).log_type

    def parse(self, line: str, parser: LogParser | None = None) -> dict[str, Any]:
        """Parse a line using the given parser or auto-detect."""
        if parser is None:
            parser = self.detect(line)
        return parser.parse(line)

    @property
    def parsers(self) -> list[LogParser]:
        return list(self._parsers)


# -----------------------------------------------------------------
# Module-level convenience functions
# -----------------------------------------------------------------
_registry = ParserRegistry()


def detect_log_type(sample: str) -> LogType:
    """Detect the log type of a sample line."""
    return _registry.detect_type(sample)


def parse_log(line: str) -> dict[str, Any]:
    """Parse a single log line using auto-detection."""
    return _registry.parse(line)


def preprocess_logs(lines: list[str], log_type: LogType | None = None) -> pd.DataFrame:
    """Parse a list of raw log lines into a structured DataFrame.

    Parameters
    ----------
    lines:
        Raw log lines.
    log_type:
        If provided, forces the use of a specific parser.
        Otherwise, the first non-empty line is used for auto-detection.
    """
    if not lines:
        return pd.DataFrame()

    if log_type is not None:
        parser = next(
            (p for p in _registry.parsers if p.log_type == log_type),
            GenericParser(),
        )
    else:
        first_line = next((ln for ln in lines if ln.strip()), "")
        parser = _registry.detect(first_line)
        log_type = parser.log_type

    logger.info("Parsing %d lines as %s", len(lines), log_type.value)

    parsed = [parser.parse(line) for line in lines if line.strip()]
    return pd.DataFrame(parsed)
