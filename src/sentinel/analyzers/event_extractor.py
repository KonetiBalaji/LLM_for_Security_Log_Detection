"""Extract security events from classified log entries."""

from __future__ import annotations

from sentinel.analyzers.entity_extraction import EntityExtractor
from sentinel.core.enums import AttackType, SeverityLevel
from sentinel.core.models import ClassificationResult, SecurityEvent

# Keyword → (AttackType, SeverityLevel) mapping
_ATTACK_SIGNATURES: list[tuple[list[str], AttackType, SeverityLevel]] = [
    (
        ["sql injection", "sqli", "union select"],
        AttackType.SQL_INJECTION,
        SeverityLevel.CRITICAL,
    ),
    (
        ["command", "exec", "shell", "cmd"],
        AttackType.COMMAND_INJECTION,
        SeverityLevel.CRITICAL,
    ),
    (
        ["file inclusion", "lfi", "rfi"],
        AttackType.FILE_INCLUSION,
        SeverityLevel.CRITICAL,
    ),
    (
        ["privilege", "escalat", "admin access"],
        AttackType.PRIVILEGE_ESCALATION,
        SeverityLevel.CRITICAL,
    ),
    (
        ["xss", "cross site", "<script"],
        AttackType.XSS,
        SeverityLevel.HIGH,
    ),
    (
        ["path traversal", "directory traversal", "../"],
        AttackType.PATH_TRAVERSAL,
        SeverityLevel.HIGH,
    ),
    (
        ["brute force", "multiple fail", "repeated attempt", "bad login"],
        AttackType.BRUTE_FORCE,
        SeverityLevel.HIGH,
    ),
    (
        ["denial", "dos", "ddos", "flood"],
        AttackType.DENIAL_OF_SERVICE,
        SeverityLevel.HIGH,
    ),
    (
        ["information disclosure", "data leak"],
        AttackType.INFORMATION_DISCLOSURE,
        SeverityLevel.MEDIUM,
    ),
    (
        ["malware", "trojan", "virus", "ransomware"],
        AttackType.MALWARE,
        SeverityLevel.CRITICAL,
    ),
]


class EventExtractor:
    """Decides which classified logs are security-relevant and builds
    :class:`SecurityEvent` objects.

    Single Responsibility: only event identification and severity assignment.
    """

    def __init__(self) -> None:
        self._entity = EntityExtractor()

    def extract(self, classified_logs: list[ClassificationResult]) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        for log in classified_logs:
            event = self._evaluate(log)
            if event is not None:
                events.append(event)
        return events

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _evaluate(self, log: ClassificationResult) -> SecurityEvent | None:
        label = log.label
        msg = log.log_message
        lower = msg.lower()

        event_type: str | None = None
        severity = SeverityLevel.LOW
        attack_type = AttackType.UNKNOWN
        requires_attention = False

        if label == "Security Alert":
            event_type = "Security Alert"
            severity = SeverityLevel.HIGH
            requires_attention = True
            attack_type, severity = self._detect_attack(lower, severity)

        elif label == "Critical Error":
            event_type = "Critical Error"
            severity = SeverityLevel.HIGH
            requires_attention = True

        elif "error" in label.lower() or "fail" in label.lower():
            event_type = label
            severity = SeverityLevel.MEDIUM

        elif label == "HTTP Status":
            status = self._entity.extract_status_code(msg)
            if status and status.startswith("4"):
                event_type = "Suspicious HTTP Activity"
                severity = SeverityLevel.LOW
                attack_type = AttackType.ENUMERATION

        elif any(kw in lower for kw in ("unauthorized", "suspicious", "unusual")):
            event_type = "Suspicious Activity"
            severity = SeverityLevel.MEDIUM
            requires_attention = True

        if event_type is None:
            return None

        return SecurityEvent(
            event_type=event_type,
            log_message=msg,
            severity=severity,
            confidence=log.confidence,
            source_ips=self._entity.extract_ips(msg),
            url_pattern=self._entity.extract_url(msg),
            attack_type=attack_type,
            http_method=self._entity.extract_http_method(msg),
            status_code=self._entity.extract_status_code(msg),
            username=self._entity.extract_username(msg),
            requires_attention=requires_attention,
        )

    @staticmethod
    def _detect_attack(
        lower: str, default_severity: SeverityLevel
    ) -> tuple[AttackType, SeverityLevel]:
        for keywords, a_type, sev in _ATTACK_SIGNATURES:
            if any(kw in lower for kw in keywords):
                return a_type, sev
        return AttackType.UNKNOWN, default_severity
