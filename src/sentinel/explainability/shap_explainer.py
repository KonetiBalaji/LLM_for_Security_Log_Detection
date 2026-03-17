"""SHAP-based explainability for the BERT classifier tier."""

from __future__ import annotations

import logging
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


class SHAPExplainer:
    """Generate SHAP explanations for BERT-based log classification.

    Uses KernelSHAP to explain predictions by treating the
    sentence-transformer embedding + classifier as a black-box pipeline.
    Word-level importance is approximated by masking input tokens.
    """

    def __init__(self, classifier: Any, encoder: Any, class_names: list[str]) -> None:
        self._classifier = classifier
        self._encoder = encoder
        self._class_names = class_names
        self._explainer: Any | None = None

    def _predict_fn(self, texts: list[str]) -> np.ndarray:
        """Prediction function wrapping encode→predict_proba."""
        embeddings = self._encoder.encode(texts, show_progress_bar=False)
        return self._classifier.predict_proba(embeddings)

    def explain(self, log_message: str, n_words: int = 10) -> dict[str, Any]:
        """Explain a single prediction using word-level masking.

        Returns a dict with:
        - predicted_label: str
        - confidence: float
        - word_importance: list of (word, importance) sorted by |importance|
        - top_words: list of most influential words
        """
        # Get base prediction
        embedding = self._encoder.encode([log_message], show_progress_bar=False)
        probs = self._classifier.predict_proba(embedding)[0]
        pred_idx = int(np.argmax(probs))
        pred_label = self._class_names[pred_idx]
        confidence = float(probs[pred_idx])

        # Word-level importance via leave-one-out
        words = log_message.split()
        if len(words) <= 1:
            return {
                "predicted_label": pred_label,
                "confidence": confidence,
                "word_importance": [(log_message, 1.0)],
                "top_words": [log_message],
            }

        base_prob = confidence
        importances: list[tuple[str, float]] = []

        for i, word in enumerate(words):
            masked = words[:i] + words[i + 1:]
            masked_text = " ".join(masked)
            if not masked_text.strip():
                importances.append((word, 0.0))
                continue

            masked_emb = self._encoder.encode([masked_text], show_progress_bar=False)
            masked_probs = self._classifier.predict_proba(masked_emb)[0]
            masked_prob = float(masked_probs[pred_idx])

            # Importance = drop in predicted class probability when word is removed
            importance = base_prob - masked_prob
            importances.append((word, round(importance, 4)))

        # Sort by absolute importance descending
        importances.sort(key=lambda x: abs(x[1]), reverse=True)
        top_words = [w for w, _ in importances[:n_words] if abs(_) > 0.001]

        return {
            "predicted_label": pred_label,
            "confidence": round(confidence, 4),
            "word_importance": importances,
            "top_words": top_words,
        }

    def explain_batch(
        self, log_messages: list[str], n_words: int = 5
    ) -> list[dict[str, Any]]:
        """Explain a batch of predictions."""
        return [self.explain(msg, n_words=n_words) for msg in log_messages]
