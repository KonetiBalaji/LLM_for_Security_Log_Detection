"""Unit tests for core domain models."""

from __future__ import annotations

from sentinel.core.enums import (
    AttackType,
    ClassificationMethod,
    LogType,
    MitreTactic,
    SeverityLevel,
)
from sentinel.core.models import (
    AnalysisResult,
    ClassificationResult,
    MitreTechnique,
    SecurityEvent,
)


class TestClassificationResult:
    def test_to_dict(self):
        r = ClassificationResult(
            source="sys1",
            log_message="test",
            label="Error",
            method=ClassificationMethod.BERT,
            confidence=0.85,
            reasoning="BERT classified it",
        )
        d = r.to_dict()
        assert d["classification"] == "Error"
        assert d["method"] == "bert"
        assert d["confidence"] == 0.85

    def test_frozen(self):
        r = ClassificationResult(
            source="a", log_message="b", label="c",
            method=ClassificationMethod.REGEX, confidence=1.0,
        )
        try:
            r.source = "x"  # type: ignore
            assert False, "Should have raised"
        except AttributeError:
            pass


class TestSecurityEvent:
    def test_to_dict_without_mitre(self):
        e = SecurityEvent(
            event_type="Error",
            log_message="test",
            severity=SeverityLevel.LOW,
            confidence=0.5,
        )
        d = e.to_dict()
        assert d["severity"] == "LOW"
        assert "mitre_technique" not in d

    def test_to_dict_with_mitre(self):
        tech = MitreTechnique(
            technique_id="T1110",
            name="Brute Force",
            tactic=MitreTactic.CREDENTIAL_ACCESS,
        )
        e = SecurityEvent(
            event_type="Security Alert",
            log_message="brute force",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            mitre_technique=tech,
        )
        d = e.to_dict()
        assert d["mitre_technique"]["technique_id"] == "T1110"
        assert d["mitre_technique"]["tactic"] == "Credential Access"

    def test_default_related_events(self):
        e = SecurityEvent(
            event_type="x", log_message="y",
            severity=SeverityLevel.INFO, confidence=0.1,
        )
        assert e.related_events == []


class TestAnalysisResult:
    def test_to_dict_empty(self):
        r = AnalysisResult()
        d = r.to_dict()
        assert d["events"] == []
        assert d["highest_severity"] is None
        assert d["requires_immediate_attention"] is False

    def test_to_dict_with_severity(self):
        r = AnalysisResult(highest_severity=SeverityLevel.CRITICAL, requires_immediate_attention=True)
        d = r.to_dict()
        assert d["highest_severity"] == "CRITICAL"
        assert d["requires_immediate_attention"] is True


class TestEnums:
    def test_severity_values(self):
        assert SeverityLevel.CRITICAL.value == "CRITICAL"

    def test_attack_type_values(self):
        assert AttackType.SQL_INJECTION.value == "SQL_INJECTION"

    def test_log_type_values(self):
        assert LogType.WEB_SERVER.value == "web_server"
        assert LogType.HDFS.value == "hdfs"

    def test_mitre_tactic_values(self):
        assert MitreTactic.INITIAL_ACCESS.value == "Initial Access"

    def test_classification_method_values(self):
        assert ClassificationMethod.REGEX.value == "regex"
        assert ClassificationMethod.BERT.value == "bert"
        assert ClassificationMethod.LLM.value == "llm"
