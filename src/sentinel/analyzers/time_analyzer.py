"""Analyse temporal patterns in classified logs."""

from __future__ import annotations

from collections import Counter
from typing import Any

from sentinel.core.models import ClassificationResult


class TimeAnalyzer:
    """Single Responsibility: temporal distribution and burst detection."""

    def analyse(self, classified_logs: list[ClassificationResult]) -> dict[str, Any]:
        label_counts: Counter[str] = Counter()
        source_counts: Counter[str] = Counter()

        for log in classified_logs:
            label_counts[log.label] += 1
            source_counts[log.source] += 1

        total = len(classified_logs)
        return {
            "total_logs": total,
            "label_distribution": dict(label_counts.most_common()),
            "source_distribution": dict(source_counts.most_common()),
        }
