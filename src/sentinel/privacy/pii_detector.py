"""PII detection and masking for security log data.

Detects and redacts personally identifiable information (PII) from log
messages before storage or transmission, supporting HIPAA, PCI-DSS,
and GDPR compliance requirements.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PIIMatch:
    """A detected PII occurrence."""

    pii_type: str
    value: str
    start: int
    end: int
    replacement: str


# ---------------------------------------------------------------------------
# Regex patterns for common PII types in log data
# ---------------------------------------------------------------------------

_PII_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
        "[EMAIL_REDACTED]",
    ),
    (
        "ssn",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "[SSN_REDACTED]",
    ),
    (
        "credit_card",
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        "[CC_REDACTED]",
    ),
    (
        "phone_us",
        re.compile(
            r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
        ),
        "[PHONE_REDACTED]",
    ),
    (
        "ipv4",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "[IP_REDACTED]",
    ),
    (
        "aws_key",
        re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
        "[AWS_KEY_REDACTED]",
    ),
    (
        "generic_secret",
        re.compile(
            r"(?i)(?:password|passwd|pwd|secret|token|api_key|apikey)\s*[=:]\s*\S+",
        ),
        "[SECRET_REDACTED]",
    ),
]


class PIIDetector:
    """Detect PII in log messages using regex patterns.

    Parameters
    ----------
    mask_ips:
        Whether to mask IP addresses. Default False because IPs are
        often needed for security analysis. Set True for HIPAA compliance.
    custom_patterns:
        Additional (name, compiled_regex, replacement) tuples.
    """

    def __init__(
        self,
        mask_ips: bool = False,
        custom_patterns: list[tuple[str, re.Pattern[str], str]] | None = None,
    ) -> None:
        self._patterns: list[tuple[str, re.Pattern[str], str]] = []
        for name, pattern, replacement in _PII_PATTERNS:
            if name == "ipv4" and not mask_ips:
                continue
            self._patterns.append((name, pattern, replacement))

        if custom_patterns:
            self._patterns.extend(custom_patterns)

    def detect(self, text: str) -> list[PIIMatch]:
        """Find all PII occurrences in *text*."""
        matches: list[PIIMatch] = []
        for pii_type, pattern, replacement in self._patterns:
            for m in pattern.finditer(text):
                matches.append(
                    PIIMatch(
                        pii_type=pii_type,
                        value=m.group(),
                        start=m.start(),
                        end=m.end(),
                        replacement=replacement,
                    )
                )
        return matches

    def mask(self, text: str) -> str:
        """Return *text* with all detected PII replaced by redaction tokens."""
        matches = self.detect(text)
        if not matches:
            return text

        # Sort by position descending so replacements don't shift indices
        matches.sort(key=lambda m: m.start, reverse=True)
        masked = text
        for m in matches:
            masked = masked[: m.start] + m.replacement + masked[m.end:]
        return masked

    def mask_batch(self, texts: list[str]) -> list[str]:
        """Mask PII in a batch of texts."""
        return [self.mask(t) for t in texts]

    def audit(self, text: str) -> dict[str, Any]:
        """Return a detection report without modifying the text."""
        matches = self.detect(text)
        return {
            "original_length": len(text),
            "pii_found": len(matches),
            "pii_types": list({m.pii_type for m in matches}),
            "details": [
                {
                    "type": m.pii_type,
                    "position": (m.start, m.end),
                    "replacement": m.replacement,
                }
                for m in matches
            ],
        }
