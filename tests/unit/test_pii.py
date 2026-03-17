"""Tests for PII detection and masking."""

from sentinel.privacy.pii_detector import PIIDetector


class TestPIIDetector:
    def setup_method(self):
        self.detector = PIIDetector()

    def test_detect_email(self):
        matches = self.detector.detect("Contact admin@example.com for help")
        types = [m.pii_type for m in matches]
        assert "email" in types

    def test_detect_ssn(self):
        matches = self.detector.detect("SSN: 123-45-6789 on record")
        types = [m.pii_type for m in matches]
        assert "ssn" in types

    def test_detect_phone(self):
        matches = self.detector.detect("Call (555) 123-4567 for support")
        types = [m.pii_type for m in matches]
        assert "phone_us" in types

    def test_detect_aws_key(self):
        matches = self.detector.detect("key=AKIAIOSFODNN7EXAMPLE is exposed")
        types = [m.pii_type for m in matches]
        assert "aws_key" in types

    def test_detect_secret(self):
        matches = self.detector.detect("password=MySuperSecret123!")
        types = [m.pii_type for m in matches]
        assert "generic_secret" in types

    def test_mask_email(self):
        result = self.detector.mask("Contact admin@example.com today")
        assert "[EMAIL_REDACTED]" in result
        assert "admin@example.com" not in result

    def test_mask_ssn(self):
        result = self.detector.mask("SSN is 123-45-6789")
        assert "[SSN_REDACTED]" in result

    def test_mask_preserves_clean_text(self):
        text = "Normal log entry with no PII"
        assert self.detector.mask(text) == text

    def test_mask_batch(self):
        texts = ["admin@test.com logged in", "Normal log"]
        results = self.detector.mask_batch(texts)
        assert "[EMAIL_REDACTED]" in results[0]
        assert results[1] == "Normal log"

    def test_audit(self):
        report = self.detector.audit("Contact admin@example.com SSN 123-45-6789")
        assert report["pii_found"] >= 2
        assert "email" in report["pii_types"]
        assert "ssn" in report["pii_types"]

    def test_ip_not_masked_by_default(self):
        result = self.detector.mask("From 192.168.1.1 to server")
        assert "192.168.1.1" in result  # IPs preserved for security analysis

    def test_ip_masked_when_enabled(self):
        detector = PIIDetector(mask_ips=True)
        result = detector.mask("From 192.168.1.1 to server")
        assert "[IP_REDACTED]" in result

    def test_no_false_positive_on_normal_log(self):
        text = "Backup completed successfully at 2025-01-01"
        matches = self.detector.detect(text)
        # Should not detect the date as PII
        pii_types = [m.pii_type for m in matches]
        assert "ssn" not in pii_types
