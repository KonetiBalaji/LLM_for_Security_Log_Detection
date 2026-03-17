"""FastAPI dependency injection providers (singletons for expensive objects)."""

from __future__ import annotations

from functools import lru_cache

from sentinel.analyzers.orchestrator import SecurityAnalyzer
from sentinel.classifiers.pipeline import ClassificationPipeline
from sentinel.core.config import SentinelSettings, get_settings


@lru_cache(maxsize=1)
def get_pipeline() -> ClassificationPipeline:
    """Singleton classification pipeline."""
    return ClassificationPipeline(settings=get_settings())


@lru_cache(maxsize=1)
def get_analyzer() -> SecurityAnalyzer:
    """Singleton security analyzer."""
    return SecurityAnalyzer()


def get_settings_dep() -> SentinelSettings:
    """Settings dependency for route handlers."""
    return get_settings()
