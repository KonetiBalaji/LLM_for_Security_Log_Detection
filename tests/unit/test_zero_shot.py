"""Tests for zero-shot evaluation sample data."""

from sentinel.evaluation.zero_shot import _ZERO_SHOT_SAMPLES


class TestZeroShotSamples:
    def test_samples_not_empty(self):
        assert len(_ZERO_SHOT_SAMPLES) > 0

    def test_all_samples_have_three_fields(self):
        for source, message, label in _ZERO_SHOT_SAMPLES:
            assert isinstance(source, str) and source
            assert isinstance(message, str) and message
            assert isinstance(label, str) and label

    def test_multiple_source_types(self):
        sources = {s for s, _, _ in _ZERO_SHOT_SAMPLES}
        # Should have at least 5 different unseen formats
        assert len(sources) >= 5

    def test_mixed_labels(self):
        labels = {l for _, _, l in _ZERO_SHOT_SAMPLES}
        assert "Security Alert" in labels
        assert "System Notification" in labels
