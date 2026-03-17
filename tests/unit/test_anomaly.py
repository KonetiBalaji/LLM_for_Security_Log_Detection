"""Tests for the Isolation Forest anomaly detector."""

from sentinel.classifiers.anomaly import AnomalyDetector
from sentinel.core.enums import ClassificationMethod


class TestAnomalyDetector:
    def test_method_is_anomaly(self):
        detector = AnomalyDetector()
        assert detector.method == ClassificationMethod.ANOMALY

    def test_not_fitted_returns_none(self):
        detector = AnomalyDetector()
        label, conf = detector.classify("some log message")
        assert label is None
        assert conf == 0.0

    def test_is_fitted_property(self):
        detector = AnomalyDetector()
        assert detector.is_fitted is False

    def test_score_batch_unfitted(self):
        detector = AnomalyDetector()
        results = detector.score_batch(["log1", "log2"])
        assert len(results) == 2
        assert results[0] == (False, 0.0)
