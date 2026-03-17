"""Custom exception hierarchy for the SENTINEL platform."""


class SentinelError(Exception):
    """Base exception for all SENTINEL errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.details = details or {}


class ParsingError(SentinelError):
    """Raised when a log line cannot be parsed."""


class ClassificationError(SentinelError):
    """Raised when log classification fails."""


class AnalysisError(SentinelError):
    """Raised when security analysis encounters an error."""


class ConfigurationError(SentinelError):
    """Raised when configuration is invalid or missing."""


class DatasetError(SentinelError):
    """Raised when dataset loading or processing fails."""


class LLMError(SentinelError):
    """Raised when LLM API call fails."""


class AuthenticationError(SentinelError):
    """Raised when API authentication fails."""
