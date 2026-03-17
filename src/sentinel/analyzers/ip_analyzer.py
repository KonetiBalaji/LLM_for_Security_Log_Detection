"""Analyse IP address frequency and identify suspicious sources."""

from __future__ import annotations

from collections import Counter
from typing import Any

from sentinel.analyzers.entity_extraction import EntityExtractor
from sentinel.core.models import ClassificationResult

# Thresholds
_HIGH_FREQ_THRESHOLD = 10
_MEDIUM_FREQ_THRESHOLD = 5


class IPAnalyzer:
    """Single Responsibility: IP frequency analysis and suspicious IP identification."""

    def __init__(self) -> None:
        self._entity = EntityExtractor()

    def analyse(self, classified_logs: list[ClassificationResult]) -> dict[str, Any]:
        """Return frequency map and suspicious IP list."""
        frequency = self._count_frequencies(classified_logs)
        suspicious = self._identify_suspicious(frequency)
        return {"frequency": frequency, "suspicious": suspicious}

    def _count_frequencies(
        self, classified_logs: list[ClassificationResult]
    ) -> dict[str, int]:
        counter: Counter[str] = Counter()
        for log in classified_logs:
            for ip in self._entity.extract_ips(log.log_message):
                counter[ip] += 1
        return dict(counter)

    @staticmethod
    def _identify_suspicious(frequency: dict[str, int]) -> list[dict[str, Any]]:
        suspicious: list[dict[str, Any]] = []
        for ip, count in sorted(frequency.items(), key=lambda x: -x[1]):
            if count >= _HIGH_FREQ_THRESHOLD:
                level = "HIGH"
            elif count >= _MEDIUM_FREQ_THRESHOLD:
                level = "MEDIUM"
            else:
                continue
            suspicious.append({
                "ip": ip,
                "request_count": count,
                "suspicion_level": level,
            })
        return suspicious
