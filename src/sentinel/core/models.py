"""Domain models for classification results, security events, and analysis output."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel.core.enums import (
    AttackType,
    ClassificationMethod,
    MitreTactic,
    SeverityLevel,
)


@dataclass(frozen=True)
class ClassificationResult:
    """Immutable result of classifying a single log entry."""

    source: str
    log_message: str
    label: str
    method: ClassificationMethod
    confidence: float
    entities: dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "log_message": self.log_message,
            "classification": self.label,
            "method": self.method.value,
            "confidence": self.confidence,
            "entities": self.entities,
            "reasoning": self.reasoning,
        }


@dataclass
class MitreTechnique:
    """Reference to a MITRE ATT&CK technique."""

    technique_id: str
    name: str
    tactic: MitreTactic
    url: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic.value,
            "url": self.url,
        }


@dataclass
class SecurityEvent:
    """A security event identified during log analysis."""

    event_type: str
    log_message: str
    severity: SeverityLevel
    confidence: float
    source_ips: list[str] = field(default_factory=list)
    url_pattern: str | None = None
    attack_type: AttackType = AttackType.UNKNOWN
    http_method: str | None = None
    status_code: str | None = None
    username: str | None = None
    timestamp: str | None = None
    requires_attention: bool = False
    root_cause: str | None = None
    recommendation: str | None = None
    mitre_technique: MitreTechnique | None = None
    related_events: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "event_type": self.event_type,
            "log_message": self.log_message,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "source_ips": self.source_ips,
            "url_pattern": self.url_pattern,
            "attack_type": self.attack_type.value,
            "http_method": self.http_method,
            "status_code": self.status_code,
            "username": self.username,
            "timestamp": self.timestamp,
            "requires_attention": self.requires_attention,
            "root_cause": self.root_cause,
            "recommendation": self.recommendation,
            "related_events": self.related_events,
        }
        if self.mitre_technique:
            result["mitre_technique"] = self.mitre_technique.to_dict()
        return result


@dataclass
class AnalysisResult:
    """Complete security analysis output."""

    events: list[SecurityEvent] = field(default_factory=list)
    grouped_events: dict[str, Any] = field(default_factory=dict)
    ip_analysis: dict[str, Any] = field(default_factory=dict)
    url_analysis: dict[str, Any] = field(default_factory=dict)
    time_analysis: dict[str, Any] = field(default_factory=dict)
    highest_severity: SeverityLevel | None = None
    requires_immediate_attention: bool = False
    summary: str = ""
    recommendations: list[str] = field(default_factory=list)
    mitre_coverage: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": [e.to_dict() for e in self.events],
            "grouped_events": self.grouped_events,
            "ip_analysis": self.ip_analysis,
            "url_analysis": self.url_analysis,
            "time_analysis": self.time_analysis,
            "highest_severity": self.highest_severity.value if self.highest_severity else None,
            "requires_immediate_attention": self.requires_immediate_attention,
            "summary": self.summary,
            "recommendations": self.recommendations,
            "mitre_coverage": self.mitre_coverage,
        }
