"""Extract structured entities (IPs, URLs, usernames) from log text."""

from __future__ import annotations

import re
from typing import Any


class EntityExtractor:
    """Stateless utility that pulls structured fields from raw log text."""

    _IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _URL_RE = re.compile(r"(?:GET|POST|PUT|DELETE|HEAD)\s+(\S+)")
    _HTTP_METHOD_RE = re.compile(
        r"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\b"
    )
    _STATUS_RE = re.compile(r"(?:status:\s*|HTTP\s*|code\s*)(\d{3})", re.IGNORECASE)
    _USERNAME_RE = re.compile(r"(?:user\s+|User)(\w+)", re.IGNORECASE)

    def extract_ips(self, text: str) -> list[str]:
        return self._IP_RE.findall(text)

    def extract_url(self, text: str) -> str | None:
        m = self._URL_RE.search(text)
        return m.group(1) if m else None

    def extract_http_method(self, text: str) -> str | None:
        m = self._HTTP_METHOD_RE.search(text)
        return m.group(1) if m else None

    def extract_status_code(self, text: str) -> str | None:
        m = self._STATUS_RE.search(text)
        return m.group(1) if m else None

    def extract_username(self, text: str) -> str | None:
        m = self._USERNAME_RE.search(text)
        return m.group(1) if m else None

    def extract_all(self, text: str) -> dict[str, Any]:
        result: dict[str, Any] = {}
        ips = self.extract_ips(text)
        if ips:
            result["ip_addresses"] = ips
        url = self.extract_url(text)
        if url:
            result["url"] = url
        method = self.extract_http_method(text)
        if method:
            result["http_method"] = method
        code = self.extract_status_code(text)
        if code:
            result["status_code"] = code
        user = self.extract_username(text)
        if user:
            result["username"] = user
        return result
