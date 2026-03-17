"""Parser for OpenStack service log format."""

from __future__ import annotations

import re
from typing import Any

from sentinel.core.enums import LogType
from sentinel.parsers.base import LogParser

_LOG_RE = re.compile(
    r'(?P<component>\S+)\s+(?P<pid>\d+)\s+(?P<level>INFO|WARNING|ERROR|CRITICAL)\s+(?P<name>[^:]+):\s+(?P<msg>.*)'
)
_DETECT_RE = re.compile(r'\S+\.\S+\s+\d+\s+(?:INFO|WARNING|ERROR|CRITICAL)\s+\S+:')


class OpenStackParser(LogParser):
    """Parse OpenStack service logs (nova, neutron, etc.)."""

    @property
    def log_type(self) -> LogType:
        return LogType.OPENSTACK

    def detect(self, sample: str) -> bool:
        return bool(_DETECT_RE.search(sample))

    def parse(self, line: str) -> dict[str, Any]:
        match = _LOG_RE.match(line)
        if not match:
            return self._fallback(line)
        return {
            "component": match.group("component"),
            "process_id": match.group("pid"),
            "level": match.group("level"),
            "name": match.group("name"),
            "message": match.group("msg"),
            "raw": line,
        }
