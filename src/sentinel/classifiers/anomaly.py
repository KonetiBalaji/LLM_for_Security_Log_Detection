"""Anomaly detection tier using Isolation Forest on log embeddings."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import numpy as np

from sentinel.classifiers.base import Classifier
from sentinel.core.enums import ClassificationMethod

logger = logging.getLogger(__name__)


class AnomalyDetector(Classifier):
    """Detect anomalous log entries using Isolation Forest on BERT embeddings.

    This classifier does NOT assign a specific label. It returns
    ``("Anomaly", score)`` for outliers and ``(None, 0.0)`` for normal
    entries, allowing the pipeline to either flag anomalies or cascade
    to the next classifier.

    Parameters
    ----------
    contamination:
        Expected proportion of anomalies in the data (0.0–0.5).
    n_estimators:
        Number of isolation trees.
    encoder_name:
        SentenceTransformer model for embeddings.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 100,
        encoder_name: str = "all-MiniLM-L6-v2",
    ) -> None:
        self._contamination = contamination
        self._n_estimators = n_estimators
        self._encoder_name = encoder_name
        self._model: Any | None = None
        self._encoder: Any | None = None
        self._is_fitted = False

    @property
    def method(self) -> ClassificationMethod:
        return ClassificationMethod.ANOMALY

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    def _get_encoder(self) -> Any:
        if self._encoder is None:
            from sentence_transformers import SentenceTransformer
            self._encoder = SentenceTransformer(self._encoder_name)
        return self._encoder

    def fit(self, log_messages: list[str]) -> None:
        """Fit the Isolation Forest on a corpus of normal log messages.

        Parameters
        ----------
        log_messages:
            List of log messages considered to be 'normal' baseline traffic.
        """
        from sklearn.ensemble import IsolationForest

        logger.info("Fitting anomaly detector on %d messages", len(log_messages))
        encoder = self._get_encoder()
        embeddings = encoder.encode(log_messages, show_progress_bar=False)

        self._model = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(embeddings)
        self._is_fitted = True
        logger.info("Anomaly detector fitted")

    def classify(self, log_message: str) -> tuple[str | None, float]:
        """Return ('Anomaly', score) if the log is an outlier, else (None, 0.0)."""
        if not self._is_fitted or self._model is None:
            return None, 0.0

        encoder = self._get_encoder()
        embedding = encoder.encode([log_message], show_progress_bar=False)

        # decision_function returns negative for outliers
        raw_score = self._model.decision_function(embedding)[0]
        prediction = self._model.predict(embedding)[0]

        if prediction == -1:  # outlier
            # Convert raw score to a 0–1 anomaly confidence
            anomaly_confidence = float(np.clip(1.0 - (raw_score + 0.5), 0.0, 1.0))
            return "Anomaly", anomaly_confidence

        return None, 0.0

    def score_batch(self, log_messages: list[str]) -> list[tuple[bool, float]]:
        """Score a batch of messages. Returns list of (is_anomaly, score)."""
        if not self._is_fitted or self._model is None:
            return [(False, 0.0)] * len(log_messages)

        encoder = self._get_encoder()
        embeddings = encoder.encode(log_messages, show_progress_bar=False)

        predictions = self._model.predict(embeddings)
        scores = self._model.decision_function(embeddings)

        results: list[tuple[bool, float]] = []
        for pred, score in zip(predictions, scores):
            is_anomaly = pred == -1
            confidence = float(np.clip(1.0 - (score + 0.5), 0.0, 1.0)) if is_anomaly else 0.0
            results.append((is_anomaly, confidence))

        return results

    def save(self, path: Path) -> None:
        """Persist fitted model."""
        import joblib
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._model, path)

    def load(self, path: Path) -> None:
        """Load pre-fitted model."""
        import joblib
        if not path.exists():
            logger.warning("Anomaly model not found at %s", path)
            return
        self._model = joblib.load(path)
        self._is_fitted = True
