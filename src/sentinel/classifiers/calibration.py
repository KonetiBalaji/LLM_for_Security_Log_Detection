"""Confidence calibration using Platt scaling and temperature scaling."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


class PlattCalibrator:
    """Platt scaling calibrator for BERT classifier probability outputs.

    Fits a sigmoid function to transform raw classifier scores into
    well-calibrated probabilities using a held-out validation set.
    """

    def __init__(self) -> None:
        self._calibrator: Any | None = None
        self._is_fitted = False

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    def fit(self, raw_probabilities: np.ndarray, true_labels: np.ndarray) -> None:
        """Fit Platt scaling on validation data.

        Parameters
        ----------
        raw_probabilities:
            Array of shape (n_samples, n_classes) from the base classifier.
        true_labels:
            Array of shape (n_samples,) with true class labels.
        """
        from sklearn.calibration import CalibratedClassifierCV
        from sklearn.base import BaseEstimator, ClassifierMixin

        class _PrecomputedClassifier(BaseEstimator, ClassifierMixin):
            """Wrapper that returns pre-computed probabilities."""

            def __init__(self, probs: np.ndarray, classes: np.ndarray) -> None:
                self.probs = probs
                self.classes_ = classes

            def fit(self, X: Any, y: Any) -> "_PrecomputedClassifier":
                return self

            def predict_proba(self, X: Any) -> np.ndarray:
                return self.probs

            def predict(self, X: Any) -> np.ndarray:
                return self.classes_[np.argmax(self.probs, axis=1)]

        classes = np.unique(true_labels)
        dummy_clf = _PrecomputedClassifier(raw_probabilities, classes)
        dummy_X = np.zeros((len(true_labels), 1))

        self._calibrator = CalibratedClassifierCV(
            estimator=dummy_clf,
            method="sigmoid",
            cv="prefit",
        )
        self._calibrator.fit(dummy_X, true_labels)
        self._is_fitted = True
        logger.info("Platt calibrator fitted on %d samples", len(true_labels))

    def calibrate(self, raw_probability: float, method: str = "bert") -> float:
        """Calibrate a single confidence score.

        If the calibrator hasn't been fitted, applies a heuristic adjustment
        based on the classification method.
        """
        if not self._is_fitted:
            return self._heuristic_calibrate(raw_probability, method)
        return float(np.clip(raw_probability, 0.0, 1.0))

    def calibrate_batch(self, probabilities: np.ndarray) -> np.ndarray:
        """Calibrate a batch of probability vectors."""
        if not self._is_fitted:
            return probabilities
        dummy_X = np.zeros((len(probabilities), 1))
        return self._calibrator.predict_proba(dummy_X)

    @staticmethod
    def _heuristic_calibrate(raw: float, method: str) -> float:
        """Heuristic adjustment when no validation data is available."""
        adjustments = {
            "regex": 0.0,       # regex is deterministic, keep as-is
            "bert": -0.05,      # ML models tend to be slightly overconfident
            "llm": -0.10,       # LLM confidence is not well-calibrated
            "anomaly": -0.05,
        }
        adj = adjustments.get(method, 0.0)
        return float(np.clip(raw + adj, 0.0, 1.0))

    def save(self, path: Path) -> None:
        """Persist calibrator to disk."""
        import joblib
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._calibrator, path)
        logger.info("Saved calibrator to %s", path)

    def load(self, path: Path) -> None:
        """Load calibrator from disk."""
        import joblib
        if not path.exists():
            logger.warning("Calibrator file not found at %s", path)
            return
        self._calibrator = joblib.load(path)
        self._is_fitted = True
        logger.info("Loaded calibrator from %s", path)


class TemperatureScaler:
    """Temperature scaling for softmax output calibration.

    Learns a single temperature parameter T that divides logits
    before softmax, optimised on validation NLL.
    """

    def __init__(self, temperature: float = 1.0) -> None:
        self.temperature = temperature

    def scale(self, logits: np.ndarray) -> np.ndarray:
        """Apply temperature scaling to logits and return calibrated probabilities."""
        scaled = logits / max(self.temperature, 1e-8)
        exp_scaled = np.exp(scaled - np.max(scaled, axis=-1, keepdims=True))
        return exp_scaled / np.sum(exp_scaled, axis=-1, keepdims=True)

    def fit(self, logits: np.ndarray, true_labels: np.ndarray) -> None:
        """Optimise temperature on validation data using grid search."""
        from sklearn.metrics import log_loss

        best_temp = 1.0
        best_loss = float("inf")

        for temp in np.arange(0.1, 5.1, 0.1):
            scaled_probs = self.scale(logits / max(temp, 1e-8) * self.temperature)
            try:
                loss = log_loss(true_labels, scaled_probs)
                if loss < best_loss:
                    best_loss = loss
                    best_temp = temp
            except ValueError:
                continue

        self.temperature = best_temp
        logger.info("Temperature scaling fitted: T=%.2f (NLL=%.4f)", best_temp, best_loss)
