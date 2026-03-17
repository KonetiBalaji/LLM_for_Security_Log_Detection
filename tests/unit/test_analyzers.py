"""Unit tests for analyzer sub-modules."""

from __future__ import annotations

import pytest

from sentinel.analyzers.entity_extraction import EntityExtractor
from sentinel.analyzers.event_extractor import EventExtractor
from sentinel.analyzers.ip_analyzer import IPAnalyzer
from sentinel.analyzers.mitre_mapper import MitreMapper
from sentinel.analyzers.recommendation import RecommendationEngine
from sentinel.analyzers.root_cause import RootCauseAnalyzer
from sentinel.analyzers.time_analyzer import TimeAnalyzer
from sentinel.analyzers.url_analyzer import URLAnalyzer
from sentinel.core.enums import AttackType, ClassificationMethod, SeverityLevel
from sentinel.core.models import ClassificationResult, SecurityEvent


# =====================================================================
# EntityExtractor
# =====================================================================
class TestEntityExtractor:
    def setup_method(self):
        self.ex = EntityExtractor()

    def test_extract_ips(self):
        ips = self.ex.extract_ips("From 10.0.0.1 to 192.168.1.1")
        assert "10.0.0.1" in ips
        assert "192.168.1.1" in ips

    def test_extract_url(self):
        url = self.ex.extract_url("GET /api/v2/users?page=1 HTTP/1.1")
        assert url == "/api/v2/users?page=1"

    def test_extract_status_code(self):
        code = self.ex.extract_status_code("status: 500 error")
        assert code == "500"

    def test_extract_username(self):
        user = self.ex.extract_username("user root executed command")
        assert user == "root"

    def test_extract_all(self):
        result = self.ex.extract_all("GET /api HTTP/1.1 from 10.0.0.1 user admin status: 200")
        assert result["ip_addresses"] == ["10.0.0.1"]
        assert result["http_method"] == "GET"
        assert result["status_code"] == "200"
        assert result["username"] == "admin"


# =====================================================================
# EventExtractor
# =====================================================================
class TestEventExtractor:
    def setup_method(self):
        self.extractor = EventExtractor()

    def test_extracts_security_alert(self):
        logs = [
            ClassificationResult(
                source="test", log_message="Brute force detected from 10.0.0.1",
                label="Security Alert", method=ClassificationMethod.BERT,
                confidence=0.95,
            ),
        ]
        events = self.extractor.extract(logs)
        assert len(events) == 1
        assert events[0].event_type == "Security Alert"
        assert events[0].severity == SeverityLevel.HIGH
        assert events[0].requires_attention is True

    def test_extracts_critical_error(self):
        logs = [
            ClassificationResult(
                source="test", log_message="Database connection crashed",
                label="Critical Error", method=ClassificationMethod.BERT,
                confidence=0.88,
            ),
        ]
        events = self.extractor.extract(logs)
        assert len(events) == 1
        assert events[0].event_type == "Critical Error"

    def test_ignores_system_notification(self):
        logs = [
            ClassificationResult(
                source="test", log_message="Backup completed successfully.",
                label="System Notification", method=ClassificationMethod.REGEX,
                confidence=1.0,
            ),
        ]
        events = self.extractor.extract(logs)
        assert len(events) == 0

    def test_detects_brute_force_attack_type(self):
        logs = [
            ClassificationResult(
                source="test", log_message="Multiple failed login attempts from 10.0.0.1",
                label="Security Alert", method=ClassificationMethod.BERT,
                confidence=0.9,
            ),
        ]
        events = self.extractor.extract(logs)
        assert events[0].attack_type == AttackType.BRUTE_FORCE

    def test_http_404_creates_suspicious_activity(self):
        logs = [
            ClassificationResult(
                source="test",
                log_message="GET /admin HTTP/1.1 status: 404",
                label="HTTP Status",
                method=ClassificationMethod.BERT,
                confidence=0.8,
            ),
        ]
        events = self.extractor.extract(logs)
        assert len(events) == 1
        assert events[0].attack_type == AttackType.ENUMERATION


# =====================================================================
# MitreMapper
# =====================================================================
class TestMitreMapper:
    def setup_method(self):
        self.mapper = MitreMapper()

    def test_maps_brute_force(self, sample_security_events):
        event = sample_security_events[0]
        self.mapper.map_event(event)
        assert event.mitre_technique is not None
        assert event.mitre_technique.technique_id == "T1110"

    def test_maps_sql_injection(self, sample_security_events):
        event = sample_security_events[1]
        self.mapper.map_event(event)
        assert event.mitre_technique is not None
        assert event.mitre_technique.technique_id == "T1190"

    def test_unknown_attack_no_mapping(self):
        event = SecurityEvent(
            event_type="Error", log_message="random error",
            severity=SeverityLevel.LOW, confidence=0.5,
            attack_type=AttackType.UNKNOWN,
        )
        self.mapper.map_event(event)
        assert event.mitre_technique is None

    def test_coverage_summary(self, sample_security_events):
        self.mapper.map_events(sample_security_events)
        summary = self.mapper.coverage_summary(sample_security_events)
        technique_ids = [t["technique_id"] for t in summary]
        assert "T1110" in technique_ids
        assert "T1190" in technique_ids

    def test_supported_techniques_not_empty(self):
        supported = MitreMapper.supported_techniques()
        assert len(supported) > 0
        assert all("technique_id" in t for t in supported)


# =====================================================================
# RecommendationEngine
# =====================================================================
class TestRecommendationEngine:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_brute_force_recommendation(self):
        event = SecurityEvent(
            event_type="Security Alert",
            log_message="Brute force from 10.0.0.1",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            attack_type=AttackType.BRUTE_FORCE,
        )
        rec = self.engine.recommend_for_event(event)
        assert "MFA" in rec or "lockout" in rec

    def test_deduplicated_batch(self, sample_security_events):
        recs = self.engine.recommend_for_events(sample_security_events)
        # Two different attack types should produce two distinct recommendations
        assert len(recs) == 2

    def test_apply_sets_recommendation_field(self, sample_security_events):
        self.engine.apply_recommendations(sample_security_events)
        for event in sample_security_events:
            assert event.recommendation is not None
            assert len(event.recommendation) > 0


# =====================================================================
# RootCauseAnalyzer
# =====================================================================
class TestRootCauseAnalyzer:
    def setup_method(self):
        self.analyzer = RootCauseAnalyzer()

    def test_auth_failure_root_cause(self):
        event = SecurityEvent(
            event_type="Security Alert",
            log_message="authentication failure for user root",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
        )
        cause = self.analyzer.analyse(event)
        assert "brute-force" in cause.lower() or "authentication" in cause.lower()

    def test_generic_root_cause(self):
        event = SecurityEvent(
            event_type="Error",
            log_message="something weird happened",
            severity=SeverityLevel.LOW,
            confidence=0.5,
        )
        cause = self.analyzer.analyse(event)
        assert "investigation" in cause.lower()


# =====================================================================
# IPAnalyzer
# =====================================================================
class TestIPAnalyzer:
    def setup_method(self):
        self.analyzer = IPAnalyzer()

    def test_counts_ip_frequency(self, sample_classified_logs):
        result = self.analyzer.analyse(sample_classified_logs)
        freq = result["frequency"]
        assert isinstance(freq, dict)

    def test_identifies_suspicious_high_frequency(self):
        # Create logs with repeated IP
        logs = [
            ClassificationResult(
                source="test",
                log_message=f"Request {i} from 10.0.0.1",
                label="HTTP Status",
                method=ClassificationMethod.BERT,
                confidence=0.8,
            )
            for i in range(15)
        ]
        result = self.analyzer.analyse(logs)
        suspicious = result["suspicious"]
        assert len(suspicious) >= 1
        assert suspicious[0]["ip"] == "10.0.0.1"
        assert suspicious[0]["suspicion_level"] == "HIGH"


# =====================================================================
# URLAnalyzer
# =====================================================================
class TestURLAnalyzer:
    def setup_method(self):
        self.analyzer = URLAnalyzer()

    def test_analyse_detects_sqli_pattern(self):
        logs = [
            ClassificationResult(
                source="test",
                log_message="GET /admin?id=1'--+OR+1=1 HTTP/1.1",
                label="HTTP Status",
                method=ClassificationMethod.BERT,
                confidence=0.8,
            ),
        ]
        result = self.analyzer.analyse(logs)
        assert len(result["suspicious_patterns"]) >= 1


# =====================================================================
# TimeAnalyzer
# =====================================================================
class TestTimeAnalyzer:
    def test_analyse_distribution(self, sample_classified_logs):
        analyzer = TimeAnalyzer()
        result = analyzer.analyse(sample_classified_logs)
        assert result["total_logs"] == len(sample_classified_logs)
        assert "label_distribution" in result
        assert "source_distribution" in result
