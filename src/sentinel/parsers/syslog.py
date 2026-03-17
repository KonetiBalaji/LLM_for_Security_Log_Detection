"""Parsers for syslog (system) and security (auth.log) formats."""

from __future__ import annotations

import re
from typing import Any

from sentinel.core.enums import LogType
from sentinel.parsers.base import LogParser

_SYSTEM_RE = re.compile(r'(?P<ts>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\w+)\s+(?P<proc>[^:]+):\s+(?P<msg>.*)')
_SECURITY_RE = re.compile(r'(?P<ts>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\w+)\s+(?P<svc>sshd|sudo|auth)\S*:\s+(?P<msg>.*)')
_DETECT_SYSTEM_RE = re.compile(r'\w{3}\s+\d+\s+\d+:\d+:\d+\s+\w+\s+\w+(\[\d+\])?:')
_DETECT_SECURITY_RE = re.compile(r'\w{3}\s+\d+\s+\d+:\d+:\d+\s+\w+\s+(sshd|sudo|auth)')


class SyslogParser(LogParser):
    """Parse standard syslog lines (e.g. /var/log/syslog)."""

    @property
    def log_type(self) -> LogType:
        return LogType.SYSLOG

    def detect(self, sample: str) -> bool:
        if _DETECT_SECURITY_RE.search(sample):
            return False  # let SecurityLogParser handle it
        return bool(_DETECT_SYSTEM_RE.search(sample))

    def parse(self, line: str) -> dict[str, Any]:
        match = _SYSTEM_RE.match(line)
        if not match:
            return self._fallback(line)
        return {
            "timestamp": match.group("ts"),
            "hostname": match.group("host"),
            "process": match.group("proc"),
            "message": match.group("msg"),
            "raw": line,
        }


class SecurityLogParser(LogParser):
    """Parse authentication / security log lines (auth.log)."""

    @property
    def log_type(self) -> LogType:
        return LogType.SECURITY

    def detect(self, sample: str) -> bool:
        return bool(_DETECT_SECURITY_RE.search(sample))

    def parse(self, line: str) -> dict[str, Any]:
        match = _SECURITY_RE.match(line)
        if not match:
            # Fall back to generic syslog parsing
            sys_match = _SYSTEM_RE.match(line)
            if sys_match:
                return {
                    "timestamp": sys_match.group("ts"),
                    "hostname": sys_match.group("host"),
                    "service": sys_match.group("proc"),
                    "message": sys_match.group("msg"),
                    "raw": line,
                }
            return self._fallback(line)
        return {
            "timestamp": match.group("ts"),
            "hostname": match.group("host"),
            "service": match.group("svc"),
            "message": match.group("msg"),
            "raw": line,
        }
