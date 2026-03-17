"""Parser for HDFS (Hadoop Distributed File System) log format."""

from __future__ import annotations

import re
from typing import Any

from sentinel.core.enums import LogType
from sentinel.parsers.base import LogParser

# HDFS log: 081109 203615 148 INFO dfs.DataNode$DataXceiver: ...
_LOG_RE = re.compile(
    r'(?P<date>\d{6})\s+(?P<time>\d{6})\s+(?P<pid>\d+)\s+'
    r'(?P<level>INFO|WARN|ERROR|FATAL)\s+(?P<component>[^:]+):\s+(?P<msg>.*)'
)
_DETECT_RE = re.compile(r'\d{6}\s+\d{6}\s+\d+\s+(?:INFO|WARN|ERROR|FATAL)\s+')

# Block ID pattern for HDFS-specific extraction
_BLOCK_RE = re.compile(r'blk_-?\d+')


class HDFSParser(LogParser):
    """Parse HDFS / Hadoop log lines from the Loghub dataset."""

    @property
    def log_type(self) -> LogType:
        return LogType.HDFS

    def detect(self, sample: str) -> bool:
        return bool(_DETECT_RE.search(sample))

    def parse(self, line: str) -> dict[str, Any]:
        match = _LOG_RE.match(line)
        if not match:
            return self._fallback(line)

        block_ids = _BLOCK_RE.findall(line)
        return {
            "date": match.group("date"),
            "time": match.group("time"),
            "process_id": match.group("pid"),
            "level": match.group("level"),
            "component": match.group("component"),
            "message": match.group("msg"),
            "block_ids": block_ids,
            "raw": line,
        }
