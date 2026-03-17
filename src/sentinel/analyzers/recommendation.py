"""Generate security recommendations based on detected events."""

from __future__ import annotations

from sentinel.core.enums import AttackType, SeverityLevel
from sentinel.core.models import SecurityEvent

_ATTACK_RECOMMENDATIONS: dict[AttackType, str] = {
    AttackType.BRUTE_FORCE: (
        "Implement account lockout policies, enable MFA, and monitor for "
        "repeated failed authentication attempts from the same source."
    ),
    AttackType.SQL_INJECTION: (
        "Review and patch the affected application. Use parameterised queries "
        "and input validation. Deploy a Web Application Firewall (WAF)."
    ),
    AttackType.XSS: (
        "Sanitise all user input, implement Content-Security-Policy headers, "
        "and review client-side JavaScript for injection vulnerabilities."
    ),
    AttackType.FILE_INCLUSION: (
        "Restrict file inclusion to a whitelist of allowed paths. Disable "
        "remote file inclusion in the server configuration."
    ),
    AttackType.COMMAND_INJECTION: (
        "Never pass user input directly to system commands. Use allow-listed "
        "parameters and sandboxed execution environments."
    ),
    AttackType.PATH_TRAVERSAL: (
        "Validate and canonicalise all file paths. Ensure the application "
        "cannot access files outside the intended directory."
    ),
    AttackType.ENUMERATION: (
        "Rate-limit requests from individual IPs. Return consistent error "
        "messages to avoid leaking information about valid resources."
    ),
    AttackType.DENIAL_OF_SERVICE: (
        "Enable rate limiting, deploy DDoS protection, and configure "
        "auto-scaling. Investigate the source IPs for potential blocking."
    ),
    AttackType.PRIVILEGE_ESCALATION: (
        "Audit user permissions immediately. Review role assignments and "
        "ensure least-privilege access. Check for known CVEs in affected services."
    ),
    AttackType.INFORMATION_DISCLOSURE: (
        "Review application error handling to prevent sensitive data leakage. "
        "Ensure stack traces and debug information are not exposed."
    ),
    AttackType.MALWARE: (
        "Isolate affected systems immediately. Run endpoint detection and "
        "response (EDR) scans. Preserve forensic evidence before remediation."
    ),
}

_SEVERITY_PREFIX: dict[SeverityLevel, str] = {
    SeverityLevel.CRITICAL: "[CRITICAL] Immediate action required — ",
    SeverityLevel.HIGH: "[HIGH] Prompt investigation needed — ",
    SeverityLevel.MEDIUM: "[MEDIUM] Schedule review — ",
    SeverityLevel.LOW: "[LOW] Monitor — ",
    SeverityLevel.INFO: "[INFO] ",
}


class RecommendationEngine:
    """Generate actionable recommendations for security events."""

    def recommend_for_event(self, event: SecurityEvent) -> str:
        """Return a recommendation string for a single event."""
        prefix = _SEVERITY_PREFIX.get(event.severity, "")
        body = _ATTACK_RECOMMENDATIONS.get(
            event.attack_type,
            "Investigate the event, review related logs, and assess impact.",
        )
        return f"{prefix}{body}"

    def recommend_for_events(self, events: list[SecurityEvent]) -> list[str]:
        """Deduplicated recommendations for a batch of events."""
        seen: set[str] = set()
        recommendations: list[str] = []
        for event in events:
            rec = self.recommend_for_event(event)
            if rec not in seen:
                seen.add(rec)
                recommendations.append(rec)
        return recommendations

    def apply_recommendations(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
        """Set the ``recommendation`` field on each event (mutates in place)."""
        for event in events:
            event.recommendation = self.recommend_for_event(event)
        return events
