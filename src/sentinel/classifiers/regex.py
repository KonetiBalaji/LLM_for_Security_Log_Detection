"""Rule-based classifier using compiled regex patterns."""

from __future__ import annotations

import re
from typing import Any

from sentinel.classifiers.base import Classifier, EntityExtractor
from sentinel.core.enums import ClassificationMethod

# Pattern → label mapping. Order matters: first match wins.
DEFAULT_PATTERNS: list[tuple[str, str]] = [
    # --- Security alerts (high priority — check first) ---
    (r".*authentication fail.*|.*login fail.*|.*failed login.*", "Security Alert"),
    (r".*unauthorized.*|.*suspicious.*|.*unusual activity.*", "Security Alert"),
    (r".*brute force.*|.*multiple failed.*|.*repeated attempt.*", "Security Alert"),
    (r".*admin.*escalat.*|.*privilege.*escalat.*", "Security Alert"),
    # --- HTTP ---
    (r".*(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/\d", "HTTP Status"),
    # --- User actions ---
    (r"User\s+\w+\s+logged\s+(?:in|out)\b", "User Action"),
    (r"Account\s+with\s+ID\s+\S+\s+created\s+by\s+", "User Action"),
    # --- System notifications ---
    (r"Backup\s+(?:started|ended|completed).*", "System Notification"),
    (r"System\s+(?:updated|reboot).*", "System Notification"),
    (r"File\s+\S+\s+uploaded\s+successfully\s+by\s+user\s+", "System Notification"),
    (r"Disk\s+cleanup\s+completed\s+successfully", "System Notification"),
    # --- Resource usage ---
    (r".*(?:memory|disk|CPU)\s+usage.*", "Resource Usage"),
    # --- Deprecation ---
    (r".*(?:deprecated|will be removed|is outdated).*", "Deprecation Warning"),
    # --- Workflow / process errors ---
    (r".*(?:workflow|process|task)\s+failed.*", "Workflow Error"),
    # --- Generic errors (keep last among error patterns) ---
    (r".*(?:error|exception|fail).*", "Error"),
]


class RegexClassifier(Classifier, EntityExtractor):
    """Fast, deterministic classification via regex patterns.

    Confidence is always 1.0 for a match (patterns are exact rules).
    Returns ``(None, 0.0)`` when no pattern matches.
    """

    def __init__(self, patterns: list[tuple[str, str]] | None = None) -> None:
        raw = patterns if patterns is not None else DEFAULT_PATTERNS
        self._patterns: list[tuple[re.Pattern[str], str]] = [
            (re.compile(p, re.IGNORECASE), label) for p, label in raw
        ]

    @property
    def method(self) -> ClassificationMethod:
        return ClassificationMethod.REGEX

    def classify(self, log_message: str) -> tuple[str | None, float]:
        for pattern, label in self._patterns:
            if pattern.search(log_message):
                return label, 1.0
        return None, 0.0

    # --- Entity extraction ---------------------------------------------------

    _IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    _HTTP_METHOD_RE = re.compile(r'\b(GET|POST|PUT|DELETE|OPTIONS|HEAD|TRACE|CONNECT)\b')
    _STATUS_CODE_RE = re.compile(r'(?:status:\s*|HTTP\s*|code\s*)(\d{3})', re.IGNORECASE)
    _USERNAME_RE = re.compile(r'(?:user\s+|User)(\w+)', re.IGNORECASE)
    _URL_RE = re.compile(r'(?:GET|POST|PUT|DELETE|HEAD)\s+(\S+)')

    def extract(self, log_message: str) -> dict[str, Any]:
        entities: dict[str, Any] = {}

        ips = self._IP_RE.findall(log_message)
        if ips:
            entities["ip_addresses"] = ips

        method_match = self._HTTP_METHOD_RE.search(log_message)
        if method_match:
            entities["http_method"] = method_match.group(1)

        status_match = self._STATUS_CODE_RE.search(log_message)
        if status_match:
            entities["status_code"] = status_match.group(1)

        user_match = self._USERNAME_RE.search(log_message)
        if user_match:
            entities["username"] = user_match.group(1)

        url_match = self._URL_RE.search(log_message)
        if url_match:
            entities["url"] = url_match.group(1)

        return entities
