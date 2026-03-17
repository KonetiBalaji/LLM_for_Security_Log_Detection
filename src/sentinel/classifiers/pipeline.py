"""Hybrid classification pipeline that orchestrates multiple classifiers."""

from __future__ import annotations

import logging
from typing import Any

from sentinel.classifiers.base import Classifier, EntityExtractor
from sentinel.classifiers.bert import BertClassifier
from sentinel.classifiers.llm import LLMClassifier
from sentinel.classifiers.regex import RegexClassifier
from sentinel.core.config import SentinelSettings, get_settings
from sentinel.core.enums import ClassificationMethod
from sentinel.core.models import ClassificationResult

logger = logging.getLogger(__name__)


class ClassificationPipeline:
    """Hybrid pipeline: Regex → BERT → LLM (cascade on failure).

    Each tier is tried in order.  The first tier that returns a label
    with confidence above its threshold wins.  This follows the
    Chain of Responsibility pattern.

    Parameters
    ----------
    classifiers:
        Ordered list of classifiers to try.  Defaults to
        ``[RegexClassifier, BertClassifier, LLMClassifier]``.
    entity_extractor:
        Extractor for structured entities (IPs, users, etc.).
    settings:
        Application configuration.
    """

    def __init__(
        self,
        classifiers: list[Classifier] | None = None,
        entity_extractor: EntityExtractor | None = None,
        settings: SentinelSettings | None = None,
    ) -> None:
        self._settings = settings or get_settings()

        if classifiers is not None:
            self._classifiers = classifiers
        else:
            self._classifiers = self._build_default_classifiers()

        self._entity_extractor = entity_extractor or RegexClassifier()

    def _build_default_classifiers(self) -> list[Classifier]:
        return [
            RegexClassifier(),
            BertClassifier(
                model_name=self._settings.bert_model_name,
                classifier_path=self._settings.classifier_model_path,
                confidence_threshold=self._settings.classifier_confidence_threshold,
            ),
            LLMClassifier(settings=self._settings),
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def classify(self, logs: list[tuple[str, str]]) -> list[ClassificationResult]:
        """Classify a batch of ``(source, log_message)`` tuples."""
        return [self.classify_single(source, msg) for source, msg in logs]

    def classify_single(self, source: str, log_message: str) -> ClassificationResult:
        """Classify a single log entry through the cascade."""
        entities = self._entity_extractor.extract(log_message)

        for classifier in self._classifiers:
            try:
                label, confidence = classifier.classify(log_message)
            except Exception:
                logger.exception(
                    "Classifier %s raised an exception, trying next tier",
                    classifier.method.value,
                )
                continue

            if label is not None:
                return ClassificationResult(
                    source=source,
                    log_message=log_message,
                    label=label,
                    method=classifier.method,
                    confidence=confidence,
                    entities=entities,
                    reasoning=self._build_reasoning(classifier.method, label, confidence),
                )

        # All classifiers declined — return Unclassified
        return ClassificationResult(
            source=source,
            log_message=log_message,
            label="Unclassified",
            method=ClassificationMethod.REGEX,
            confidence=0.0,
            entities=entities,
            reasoning="No classifier was able to categorise this log entry.",
        )

    @staticmethod
    def _build_reasoning(method: ClassificationMethod, label: str, confidence: float) -> str:
        if method == ClassificationMethod.REGEX:
            return "Matched rule-based pattern."
        if method == ClassificationMethod.BERT:
            return f"Classified with BERT embeddings (confidence: {confidence:.2f})."
        if method == ClassificationMethod.LLM:
            return f"Classified via LLM analysis (confidence: {confidence:.2f})."
        return ""

    # ------------------------------------------------------------------
    # CSV helper (backward-compatible with original classify_csv)
    # ------------------------------------------------------------------
    def classify_csv(self, input_path: str, output_path: str = "output.csv") -> str:
        """Read a CSV, classify every row, write results."""
        import pandas as pd

        df = pd.read_csv(input_path)
        required = {"source", "log_message"}
        if not required.issubset(df.columns):
            missing = required - set(df.columns)
            raise ValueError(f"CSV missing required columns: {missing}")

        results = self.classify(list(zip(df["source"], df["log_message"])))

        df["target_label"] = [r.label for r in results]
        df["method"] = [r.method.value for r in results]
        df["confidence"] = [r.confidence for r in results]
        df["reasoning"] = [r.reasoning for r in results]

        df.to_csv(output_path, index=False)
        return output_path
