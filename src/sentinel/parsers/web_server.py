"""Parser for Apache / Nginx common and combined log formats."""

from __future__ import annotations

import re
from typing import Any

from sentinel.core.enums import LogType
from sentinel.parsers.base import LogParser

_LOG_RE = re.compile(
    r'(?P<ip>[\d.]+)\s+-\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)" \s*(?P<status>\d+)\s+(?P<bytes>\d+)'
)
_DETECT_RE = re.compile(
    r'[\d.]+\s+-\s+.*\[.*\]\s+"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+.*HTTP/\d\.\d"\s+\d+\s+\d+'
)


class WebServerParser(LogParser):
    """Parse Apache / Nginx access log lines."""

    @property
    def log_type(self) -> LogType:
        return LogType.WEB_SERVER

    def detect(self, sample: str) -> bool:
        return bool(_DETECT_RE.search(sample))

    def parse(self, line: str) -> dict[str, Any]:
        match = _LOG_RE.match(line)
        if not match:
            return self._fallback(line)

        request = match.group("request")
        parts = request.split()
        return {
            "ip_address": match.group("ip"),
            "timestamp": match.group("timestamp"),
            "request": request,
            "http_method": parts[0] if parts else "",
            "url": parts[1] if len(parts) > 1 else "",
            "protocol": parts[2] if len(parts) > 2 else "",
            "status_code": match.group("status"),
            "bytes_sent": match.group("bytes"),
            "raw": line,
        }
