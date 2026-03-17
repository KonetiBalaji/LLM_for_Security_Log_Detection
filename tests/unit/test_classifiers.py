"""Unit tests for classifiers."""

from __future__ import annotations

import pytest

from sentinel.classifiers.llm import SimulatedLLMClassifier
from sentinel.classifiers.regex import RegexClassifier
from sentinel.core.enums import ClassificationMethod


# =====================================================================
# RegexClassifier
# =====================================================================
class TestRegexClassifier:
    def setup_method(self):
        self.clf = RegexClassifier()

    def test_method_is_regex(self):
        assert self.clf.method == ClassificationMethod.REGEX

    def test_classify_security_alert(self):
        label, conf = self.clf.classify("Multiple failed login attempts detected")
        assert label == "Security Alert"
        assert conf == 1.0

    def test_classify_system_notification(self):
        label, conf = self.clf.classify("Backup completed successfully.")
        assert label == "System Notification"
        assert conf == 1.0

    def test_classify_user_action(self):
        label, conf = self.clf.classify("User admin logged in.")
        assert label == "User Action"
        assert conf == 1.0

    def test_classify_http_status(self):
        label, conf = self.clf.classify("GET /api/users HTTP/1.1 200 OK")
        assert label == "HTTP Status"
        assert conf == 1.0

    def test_classify_resource_usage(self):
        label, conf = self.clf.classify("Server memory usage at 95%")
        assert label == "Resource Usage"
        assert conf == 1.0

    def test_classify_deprecation(self):
        label, conf = self.clf.classify("This API is deprecated and will be removed in v5.0")
        assert label == "Deprecation Warning"
        assert conf == 1.0

    def test_classify_returns_none_for_unknown(self):
        label, conf = self.clf.classify("Hello world, this is a random message")
        assert label is None
        assert conf == 0.0

    def test_classify_case_insensitive(self):
        label, _ = self.clf.classify("UNAUTHORIZED ACCESS DETECTED")
        assert label == "Security Alert"

    def test_classify_brute_force(self):
        label, _ = self.clf.classify("Brute force attack from 10.0.0.1")
        assert label == "Security Alert"

    def test_classify_privilege_escalation(self):
        label, _ = self.clf.classify("Admin access escalation detected for user 9429")
        assert label == "Security Alert"


# =====================================================================
# RegexClassifier Entity Extraction
# =====================================================================
class TestRegexEntityExtraction:
    def setup_method(self):
        self.clf = RegexClassifier()

    def test_extract_ip_addresses(self):
        entities = self.clf.extract("Connection from 192.168.1.1 to 10.0.0.1")
        assert "192.168.1.1" in entities["ip_addresses"]
        assert "10.0.0.1" in entities["ip_addresses"]

    def test_extract_http_method(self):
        entities = self.clf.extract("GET /api/health HTTP/1.1")
        assert entities["http_method"] == "GET"

    def test_extract_status_code(self):
        entities = self.clf.extract("status: 404 not found")
        assert entities["status_code"] == "404"

    def test_extract_username(self):
        entities = self.clf.extract("user admin performed action")
        assert entities["username"] == "admin"

    def test_extract_empty_for_plain_text(self):
        entities = self.clf.extract("nothing special here")
        assert entities == {}


# =====================================================================
# SimulatedLLMClassifier
# =====================================================================
class TestSimulatedLLMClassifier:
    def setup_method(self):
        self.clf = SimulatedLLMClassifier()

    def test_method_is_llm(self):
        assert self.clf.method == ClassificationMethod.LLM

    def test_classify_security(self):
        label, conf = self.clf.classify("Unauthorized access attempt detected")
        assert label == "Security Alert"
        assert conf == 0.70

    def test_classify_error(self):
        label, _ = self.clf.classify("Critical system error occurred")
        assert label == "Critical Error"

    def test_classify_http(self):
        label, _ = self.clf.classify("GET /api/users returned status: 200")
        assert label == "HTTP Status"

    def test_classify_unclassified(self):
        label, conf = self.clf.classify("The sky is blue today")
        assert label == "Unclassified"
        assert conf == 0.0

    def test_reasoning_includes_simulated_tag(self):
        result = self.clf.classify_with_reasoning("Backup completed")
        assert "[Simulated]" in result["reasoning"]

    def test_deprecation(self):
        label, _ = self.clf.classify("This feature is deprecated and will be removed")
        assert label == "Deprecation Warning"
