"""Integration tests for the full classification + analysis pipeline."""

from __future__ import annotations

import pytest

from sentinel.analyzers.orchestrator import SecurityAnalyzer
from sentinel.classifiers.llm import SimulatedLLMClassifier
from sentinel.classifiers.pipeline import ClassificationPipeline
from sentinel.classifiers.regex import RegexClassifier
from sentinel.core.enums import ClassificationMethod


class TestClassificationPipeline:
    """Test the hybrid pipeline end-to-end without BERT (to avoid model download in CI)."""

    def setup_method(self):
        # Use only regex + simulated LLM (no BERT model needed)
        self.pipeline = ClassificationPipeline(
            classifiers=[RegexClassifier(), SimulatedLLMClassifier()],
        )

    def test_classify_single_regex_match(self):
        result = self.pipeline.classify_single("TestSys", "Backup completed successfully.")
        assert result.label == "System Notification"
        assert result.method == ClassificationMethod.REGEX
        assert result.confidence == 1.0

    def test_classify_single_falls_to_llm(self):
        result = self.pipeline.classify_single("TestSys", "Database connection timeout at 3am")
        # This won't match regex, so should fall to SimulatedLLM
        assert result.label is not None
        assert result.method == ClassificationMethod.LLM

    def test_classify_batch(self):
        logs = [
            ("SysA", "User admin logged in."),
            ("SysB", "CPU usage at 95%"),
            ("SysC", "Random nonsensical gibberish xyz"),
        ]
        results = self.pipeline.classify(logs)
        assert len(results) == 3
        assert results[0].label == "User Action"
        assert results[1].label == "Resource Usage"

    def test_classify_security_alert(self):
        result = self.pipeline.classify_single("SysA", "Multiple failed login attempts from 10.0.0.1")
        assert result.label == "Security Alert"

    def test_entities_extracted(self):
        result = self.pipeline.classify_single("SysA", "GET /api/test HTTP/1.1 from 192.168.1.1 status: 200")
        assert "ip_addresses" in result.entities
        assert "192.168.1.1" in result.entities["ip_addresses"]


class TestFullAnalysisPipeline:
    """Test classification → analysis end-to-end."""

    def test_full_pipeline(self):
        pipeline = ClassificationPipeline(
            classifiers=[RegexClassifier(), SimulatedLLMClassifier()],
        )
        analyzer = SecurityAnalyzer()

        logs = [
            ("WebServer", "Multiple failed login attempts from 10.0.0.1"),
            ("WebServer", "Backup completed successfully."),
            ("WebServer", "SQL injection attempt: GET /admin?id=1' OR 1=1-- HTTP/1.1"),
            ("WebServer", "User admin logged in."),
            ("WebServer", "System crashed due to memory overflow"),
        ]

        classified = pipeline.classify(logs)
        assert len(classified) == 5

        result = analyzer.analyze(classified)

        # Should detect security events
        assert len(result.events) > 0
        assert result.summary != ""
        assert isinstance(result.recommendations, list)

        # MITRE mapping should be populated for security events
        mitre_events = [e for e in result.events if e.mitre_technique is not None]
        assert len(mitre_events) > 0

        # Root cause should be populated
        for event in result.events:
            assert event.root_cause is not None

        # Recommendation should be populated
        for event in result.events:
            assert event.recommendation is not None

    def test_analysis_with_no_security_events(self):
        pipeline = ClassificationPipeline(
            classifiers=[RegexClassifier(), SimulatedLLMClassifier()],
        )
        analyzer = SecurityAnalyzer()

        logs = [
            ("Sys", "Backup completed successfully."),
            ("Sys", "User admin logged in."),
        ]

        classified = pipeline.classify(logs)
        result = analyzer.analyze(classified)

        assert len(result.events) == 0
        assert result.requires_immediate_attention is False
        assert "No security events" in result.summary
