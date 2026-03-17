"""SecurityAnalyzer facade — composes all sub-analyzers into a single API."""

from __future__ import annotations

import logging

from sentinel.analyzers.event_extractor import EventExtractor
from sentinel.analyzers.ip_analyzer import IPAnalyzer
from sentinel.analyzers.mitre_mapper import MitreMapper
from sentinel.analyzers.recommendation import RecommendationEngine
from sentinel.analyzers.root_cause import RootCauseAnalyzer
from sentinel.analyzers.time_analyzer import TimeAnalyzer
from sentinel.analyzers.url_analyzer import URLAnalyzer
from sentinel.core.enums import SeverityLevel
from sentinel.core.models import AnalysisResult, ClassificationResult, SecurityEvent

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """High-level facade that delegates to focused sub-analyzers.

    This is intentionally thin — each sub-module owns its own logic.
    Follows the Facade pattern and keeps this class under ~60 lines.
    """

    def __init__(self) -> None:
        self._event_extractor = EventExtractor()
        self._ip_analyzer = IPAnalyzer()
        self._url_analyzer = URLAnalyzer()
        self._time_analyzer = TimeAnalyzer()
        self._mitre_mapper = MitreMapper()
        self._root_cause = RootCauseAnalyzer()
        self._recommendations = RecommendationEngine()

    def analyze(self, classified_logs: list[ClassificationResult]) -> AnalysisResult:
        """Run the full analysis pipeline and return an :class:`AnalysisResult`."""

        # 1. Extract security events
        events = self._event_extractor.extract(classified_logs)
        logger.info("Extracted %d security events from %d logs", len(events), len(classified_logs))

        # 2. Enrich with root cause
        self._root_cause.apply(events)

        # 3. Map to MITRE ATT&CK
        self._mitre_mapper.map_events(events)

        # 4. Generate per-event recommendations
        self._recommendations.apply_recommendations(events)

        # 5. Aggregate recommendations
        all_recommendations = self._recommendations.recommend_for_events(events)

        # 6. IP / URL / Time analysis
        ip_analysis = self._ip_analyzer.analyse(classified_logs)
        url_analysis = self._url_analyzer.analyse(classified_logs)
        time_analysis = self._time_analyzer.analyse(classified_logs)

        # 7. MITRE coverage
        mitre_coverage = self._mitre_mapper.coverage_summary(events)

        # 8. Determine highest severity
        highest = self._highest_severity(events)

        # 9. Build summary
        summary = self._build_summary(events, classified_logs, ip_analysis)

        return AnalysisResult(
            events=events,
            ip_analysis=ip_analysis,
            url_analysis=url_analysis,
            time_analysis=time_analysis,
            highest_severity=highest,
            requires_immediate_attention=highest in (SeverityLevel.CRITICAL, SeverityLevel.HIGH),
            summary=summary,
            recommendations=all_recommendations,
            mitre_coverage=mitre_coverage,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _highest_severity(events: list[SecurityEvent]) -> SeverityLevel | None:
        if not events:
            return None
        order = [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM,
                 SeverityLevel.LOW, SeverityLevel.INFO]
        for level in order:
            if any(e.severity == level for e in events):
                return level
        return None

    @staticmethod
    def _build_summary(
        events: list[SecurityEvent],
        classified_logs: list[ClassificationResult],
        ip_analysis: dict,
    ) -> str:
        n_events = len(events)
        n_logs = len(classified_logs)
        n_suspicious_ips = len(ip_analysis.get("suspicious", []))
        critical = sum(1 for e in events if e.severity == SeverityLevel.CRITICAL)
        high = sum(1 for e in events if e.severity == SeverityLevel.HIGH)

        parts = [f"Analysed {n_logs} log entries, identified {n_events} security events."]
        if critical:
            parts.append(f"{critical} CRITICAL severity event(s) require immediate attention.")
        if high:
            parts.append(f"{high} HIGH severity event(s) detected.")
        if n_suspicious_ips:
            parts.append(f"{n_suspicious_ips} suspicious IP address(es) identified.")
        if n_events == 0:
            parts.append("No security events detected in the analysed logs.")
        return " ".join(parts)
