"""Analyse URL patterns for potential attack indicators."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from sentinel.analyzers.entity_extraction import EntityExtractor
from sentinel.core.models import ClassificationResult

_SQLI_RE = re.compile(r"(%27|'|--|/\*|%23|#)", re.IGNORECASE)
_XSS_RE = re.compile(r"(<script|%3Cscript|%3C%2Fscript)", re.IGNORECASE)
_PATH_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f)", re.IGNORECASE)


class URLAnalyzer:
    """Single Responsibility: URL pattern frequency and attack pattern detection."""

    def __init__(self) -> None:
        self._entity = EntityExtractor()

    def analyse(self, classified_logs: list[ClassificationResult]) -> dict[str, Any]:
        url_counter: Counter[str] = Counter()
        suspicious_patterns: list[dict[str, str]] = []

        for log in classified_logs:
            url = self._entity.extract_url(log.log_message)
            if url is None:
                continue

            path = url.split("?")[0]
            url_counter[path] += 1

            for pattern, name in [
                (_SQLI_RE, "Potential SQL Injection"),
                (_XSS_RE, "Potential XSS"),
                (_PATH_TRAVERSAL_RE, "Potential Path Traversal"),
            ]:
                if pattern.search(url):
                    suspicious_patterns.append({"url": url, "pattern": name})

        return {
            "top_urls": dict(url_counter.most_common(20)),
            "suspicious_patterns": suspicious_patterns,
            "total_unique_urls": len(url_counter),
        }
