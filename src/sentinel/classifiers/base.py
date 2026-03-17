"""Abstract base for all classifiers (Open/Closed principle)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from sentinel.core.enums import ClassificationMethod


class Classifier(ABC):
    """Every classifier must implement ``classify`` and declare its method."""

    @property
    @abstractmethod
    def method(self) -> ClassificationMethod:
        """Which classification method this represents."""

    @abstractmethod
    def classify(self, log_message: str) -> tuple[str | None, float]:
        """Classify a log message.

        Returns
        -------
        tuple[str | None, float]
            ``(label, confidence)`` where *label* is ``None`` when the
            classifier declines to classify (e.g. no regex match).
        """


class EntityExtractor(ABC):
    """Extracts structured entities (IPs, users, etc.) from log text."""

    @abstractmethod
    def extract(self, log_message: str) -> dict[str, Any]:
        """Return a dict of extracted entities."""
