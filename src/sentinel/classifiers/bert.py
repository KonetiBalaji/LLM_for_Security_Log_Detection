"""BERT-embedding classifier using SentenceTransformer + scikit-learn."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np

from sentinel.classifiers.base import Classifier
from sentinel.core.enums import ClassificationMethod
from sentinel.core.exceptions import ClassificationError

if TYPE_CHECKING:
    from sklearn.linear_model import LogisticRegression

logger = logging.getLogger(__name__)

# Labels the model was trained on (must match training data)
TRAINED_LABELS = [
    "HTTP Status",
    "Security Alert",
    "Critical Error",
    "Error",
    "System Notification",
    "User Action",
    "Resource Usage",
    "Workflow Error",
    "Deprecation Warning",
]


class BertClassifier(Classifier):
    """Classify using sentence-transformer embeddings + logistic regression.

    Parameters
    ----------
    model_name:
        HuggingFace model id for the SentenceTransformer encoder.
    classifier_path:
        Path to a joblib-serialised scikit-learn classifier.  If the file does
        not exist, a warning is logged and ``classify`` always declines.
    confidence_threshold:
        Minimum probability to accept a prediction.
    """

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        classifier_path: Path | None = None,
        confidence_threshold: float = 0.5,
    ) -> None:
        self._model_name = model_name
        self._confidence_threshold = confidence_threshold
        self._encoder: object | None = None  # lazy load
        self._classifier: LogisticRegression | None = None
        self._classifier_path = classifier_path

    @property
    def method(self) -> ClassificationMethod:
        return ClassificationMethod.BERT

    # ------------------------------------------------------------------
    # Lazy loading (avoids heavy imports / downloads at import time)
    # ------------------------------------------------------------------
    def _get_encoder(self) -> object:
        if self._encoder is None:
            from sentence_transformers import SentenceTransformer
            logger.info("Loading SentenceTransformer: %s", self._model_name)
            self._encoder = SentenceTransformer(self._model_name)
        return self._encoder

    def _get_classifier(self) -> LogisticRegression | None:
        if self._classifier is not None:
            return self._classifier

        if self._classifier_path is None or not self._classifier_path.exists():
            logger.warning(
                "Classifier model not found at %s — BERT tier will decline all inputs.",
                self._classifier_path,
            )
            return None

        import joblib
        self._classifier = joblib.load(self._classifier_path)
        logger.info("Loaded classifier from %s", self._classifier_path)
        return self._classifier

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def embed(self, text: str) -> np.ndarray:
        """Return the embedding vector for *text*."""
        encoder = self._get_encoder()
        return encoder.encode([text])[0]  # type: ignore[union-attr]

    def classify(self, log_message: str) -> tuple[str | None, float]:
        clf = self._get_classifier()
        if clf is None:
            return None, 0.0

        try:
            encoder = self._get_encoder()
            embedding = encoder.encode([log_message])  # type: ignore[union-attr]
            probabilities = clf.predict_proba(embedding)[0]
            best_idx = int(np.argmax(probabilities))
            confidence = float(probabilities[best_idx])
            label = str(clf.classes_[best_idx])

            if confidence < self._confidence_threshold:
                return None, confidence

            return label, confidence

        except Exception as exc:
            logger.error("BERT classification failed: %s", exc)
            raise ClassificationError(
                f"BERT classification failed: {exc}",
                details={"log_message": log_message[:200]},
            ) from exc
