"""Tests for confidence calibration."""

import numpy as np

from sentinel.classifiers.calibration import PlattCalibrator, TemperatureScaler


class TestPlattCalibrator:
    def test_heuristic_calibrate_regex(self):
        cal = PlattCalibrator()
        assert cal.calibrate(1.0, "regex") == 1.0

    def test_heuristic_calibrate_bert(self):
        cal = PlattCalibrator()
        result = cal.calibrate(0.9, "bert")
        assert result == 0.85  # 0.9 - 0.05

    def test_heuristic_calibrate_llm(self):
        cal = PlattCalibrator()
        result = cal.calibrate(0.8, "llm")
        assert abs(result - 0.7) < 1e-9  # 0.8 - 0.10

    def test_heuristic_clamps_to_zero(self):
        cal = PlattCalibrator()
        result = cal.calibrate(0.03, "llm")
        assert result == 0.0

    def test_not_fitted_by_default(self):
        cal = PlattCalibrator()
        assert cal.is_fitted is False


class TestTemperatureScaler:
    def test_default_temperature(self):
        scaler = TemperatureScaler()
        assert scaler.temperature == 1.0

    def test_scale_produces_valid_probabilities(self):
        scaler = TemperatureScaler(temperature=1.5)
        logits = np.array([[2.0, 1.0, 0.5]])
        probs = scaler.scale(logits)
        assert probs.shape == (1, 3)
        assert abs(probs.sum() - 1.0) < 1e-6
        assert all(p >= 0 for p in probs[0])

    def test_high_temperature_flattens_distribution(self):
        scaler_low = TemperatureScaler(temperature=0.5)
        scaler_high = TemperatureScaler(temperature=3.0)
        logits = np.array([[3.0, 1.0, 0.1]])

        probs_low = scaler_low.scale(logits)
        probs_high = scaler_high.scale(logits)

        # High temperature should make distribution more uniform
        assert probs_high[0].std() < probs_low[0].std()
