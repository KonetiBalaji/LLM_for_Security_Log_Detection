"""Rule-based root cause analysis for security events."""

from __future__ import annotations

from sentinel.core.models import SecurityEvent


_ROOT_CAUSE_RULES: list[tuple[list[str], str]] = [
    (
        ["authentication fail", "login fail", "failed login", "invalid password"],
        "Authentication failure — likely incorrect credentials or a brute-force attempt.",
    ),
    (
        ["sql injection", "sqli", "union select", "'--", "or 1=1"],
        "SQL injection attempt targeting an unvalidated input field.",
    ),
    (
        ["xss", "<script", "cross site"],
        "Cross-site scripting attempt via malicious script injection.",
    ),
    (
        ["privilege escalat", "admin access", "root access"],
        "Privilege escalation attempt — a user or process tried to gain elevated access.",
    ),
    (
        ["denied", "forbidden", "403"],
        "Access denied — the request was blocked by authorisation controls.",
    ),
    (
        ["timeout", "timed out", "connection refused"],
        "Service connectivity failure — the target service is unreachable or overloaded.",
    ),
    (
        ["disk", "storage", "no space"],
        "Storage exhaustion — the system ran out of available disk space.",
    ),
    (
        ["memory", "out of memory", "oom"],
        "Memory exhaustion — the process exceeded available RAM.",
    ),
    (
        ["crash", "segfault", "core dump"],
        "Process crash — likely a software bug or corrupted state.",
    ),
    (
        ["certificate", "ssl", "tls", "handshake"],
        "TLS/SSL failure — certificate expired, untrusted, or handshake error.",
    ),
]


class RootCauseAnalyzer:
    """Determine probable root cause for a security event using keyword rules."""

    def analyse(self, event: SecurityEvent) -> str:
        lower = event.log_message.lower()
        for keywords, explanation in _ROOT_CAUSE_RULES:
            if any(kw in lower for kw in keywords):
                return explanation
        return f"Event of type '{event.event_type}' detected — manual investigation recommended."

    def apply(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
        """Set ``root_cause`` on each event (mutates in place)."""
        for event in events:
            event.root_cause = self.analyse(event)
        return events
