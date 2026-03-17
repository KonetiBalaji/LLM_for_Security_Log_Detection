"""Feedback storage and retrieval for analyst-in-the-loop learning."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FeedbackEntry:
    """A single analyst feedback record."""

    id: str = field(default_factory=lambda: str(uuid4()))
    log_message: str = ""
    predicted_label: str = ""
    predicted_confidence: float = 0.0
    predicted_method: str = ""
    is_correct: bool = True
    correct_label: str | None = None
    analyst_id: str = ""
    notes: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class FeedbackStore:
    """File-backed feedback store for analyst corrections.

    Stores feedback as newline-delimited JSON (NDJSON) for simplicity.
    In production, this would be backed by a database.

    Parameters
    ----------
    store_path:
        Path to the NDJSON feedback file.
    """

    def __init__(self, store_path: Path | None = None) -> None:
        if store_path is None:
            from sentinel.core.config import get_settings
            settings = get_settings()
            store_path = Path(settings.project_root) / "data" / "feedback.ndjson"
        self._path = store_path

    def submit(self, entry: FeedbackEntry) -> str:
        """Record a feedback entry. Returns the entry ID."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry), default=str) + "\n")
        logger.info("Feedback recorded: id=%s correct=%s", entry.id, entry.is_correct)
        return entry.id

    def get_all(self) -> list[FeedbackEntry]:
        """Retrieve all feedback entries."""
        if not self._path.exists():
            return []

        entries: list[FeedbackEntry] = []
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    entries.append(FeedbackEntry(**data))
        return entries

    def get_corrections(self) -> list[FeedbackEntry]:
        """Return only entries where the analyst corrected the label."""
        return [e for e in self.get_all() if not e.is_correct and e.correct_label]

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics of collected feedback."""
        entries = self.get_all()
        total = len(entries)
        if total == 0:
            return {"total": 0, "correct": 0, "incorrect": 0, "accuracy": 0.0}

        correct = sum(1 for e in entries if e.is_correct)
        incorrect = total - correct

        # Breakdown by method
        method_stats: dict[str, dict[str, int]] = {}
        for e in entries:
            m = e.predicted_method or "unknown"
            if m not in method_stats:
                method_stats[m] = {"correct": 0, "incorrect": 0}
            if e.is_correct:
                method_stats[m]["correct"] += 1
            else:
                method_stats[m]["incorrect"] += 1

        return {
            "total": total,
            "correct": correct,
            "incorrect": incorrect,
            "accuracy": round(correct / total, 4),
            "by_method": method_stats,
        }

    def export_training_data(self) -> list[tuple[str, str]]:
        """Export corrections as (log_message, correct_label) for retraining."""
        corrections = self.get_corrections()
        return [
            (e.log_message, e.correct_label)
            for e in corrections
            if e.correct_label is not None
        ]

    def clear(self) -> None:
        """Remove all feedback data."""
        if self._path.exists():
            self._path.unlink()
            logger.info("Feedback store cleared")
