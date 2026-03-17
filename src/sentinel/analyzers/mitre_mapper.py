"""Map detected attack types to MITRE ATT&CK Enterprise techniques."""

from __future__ import annotations

from sentinel.core.enums import AttackType, MitreTactic
from sentinel.core.models import MitreTechnique, SecurityEvent

_ATTACK_URL = "https://attack.mitre.org/techniques"

# Mapping: AttackType → MitreTechnique
_MITRE_MAP: dict[AttackType, MitreTechnique] = {
    AttackType.BRUTE_FORCE: MitreTechnique(
        technique_id="T1110",
        name="Brute Force",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        url=f"{_ATTACK_URL}/T1110",
    ),
    AttackType.SQL_INJECTION: MitreTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic=MitreTactic.INITIAL_ACCESS,
        url=f"{_ATTACK_URL}/T1190",
    ),
    AttackType.XSS: MitreTechnique(
        technique_id="T1189",
        name="Drive-by Compromise",
        tactic=MitreTactic.INITIAL_ACCESS,
        url=f"{_ATTACK_URL}/T1189",
    ),
    AttackType.FILE_INCLUSION: MitreTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic=MitreTactic.INITIAL_ACCESS,
        url=f"{_ATTACK_URL}/T1190",
    ),
    AttackType.COMMAND_INJECTION: MitreTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic=MitreTactic.EXECUTION,
        url=f"{_ATTACK_URL}/T1059",
    ),
    AttackType.PATH_TRAVERSAL: MitreTechnique(
        technique_id="T1083",
        name="File and Directory Discovery",
        tactic=MitreTactic.DISCOVERY,
        url=f"{_ATTACK_URL}/T1083",
    ),
    AttackType.ENUMERATION: MitreTechnique(
        technique_id="T1046",
        name="Network Service Scanning",
        tactic=MitreTactic.DISCOVERY,
        url=f"{_ATTACK_URL}/T1046",
    ),
    AttackType.DENIAL_OF_SERVICE: MitreTechnique(
        technique_id="T1499",
        name="Endpoint Denial of Service",
        tactic=MitreTactic.IMPACT,
        url=f"{_ATTACK_URL}/T1499",
    ),
    AttackType.PRIVILEGE_ESCALATION: MitreTechnique(
        technique_id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic=MitreTactic.PRIVILEGE_ESCALATION,
        url=f"{_ATTACK_URL}/T1068",
    ),
    AttackType.INFORMATION_DISCLOSURE: MitreTechnique(
        technique_id="T1005",
        name="Data from Local System",
        tactic=MitreTactic.COLLECTION,
        url=f"{_ATTACK_URL}/T1005",
    ),
    AttackType.MALWARE: MitreTechnique(
        technique_id="T1204",
        name="User Execution",
        tactic=MitreTactic.EXECUTION,
        url=f"{_ATTACK_URL}/T1204",
    ),
}


class MitreMapper:
    """Enrich :class:`SecurityEvent` objects with MITRE ATT&CK references."""

    def map_event(self, event: SecurityEvent) -> SecurityEvent:
        """Add MITRE technique to an event (mutates in place and returns it)."""
        technique = _MITRE_MAP.get(event.attack_type)
        if technique is not None:
            event.mitre_technique = technique
        return event

    def map_events(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
        """Map all events in a batch."""
        for event in events:
            self.map_event(event)
        return events

    def coverage_summary(self, events: list[SecurityEvent]) -> list[dict[str, str]]:
        """Return a deduplicated list of MITRE techniques observed."""
        seen: dict[str, dict[str, str]] = {}
        for event in events:
            if event.mitre_technique and event.mitre_technique.technique_id not in seen:
                seen[event.mitre_technique.technique_id] = event.mitre_technique.to_dict()
        return list(seen.values())

    @staticmethod
    def supported_techniques() -> list[dict[str, str]]:
        """All techniques this mapper can assign."""
        return [t.to_dict() for t in _MITRE_MAP.values()]
