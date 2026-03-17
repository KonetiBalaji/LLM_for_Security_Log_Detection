"""Application configuration using Pydantic Settings."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _project_root() -> Path:
    """Resolve project root directory (contains pyproject.toml)."""
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / "pyproject.toml").exists():
            return parent
    return Path.cwd()


class SentinelSettings(BaseSettings):
    """Central configuration loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- LLM ---
    llm_provider: str = "openai"
    openai_api_key: Optional[str] = Field(default=None)
    llm_model: str = "gpt-4o-mini"
    llm_temperature: float = 0.2
    llm_max_tokens: int = 500
    llm_timeout_seconds: int = 30

    # --- BERT / ML ---
    bert_model_name: str = "all-MiniLM-L6-v2"
    classifier_confidence_threshold: float = 0.5

    # --- Paths ---
    project_root: Path = Field(default_factory=_project_root)
    data_dir: Optional[Path] = None
    model_dir: Optional[Path] = None

    # --- Server ---
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"
    max_upload_size_mb: int = 50

    # --- Auth ---
    auth_enabled: bool = False
    auth_token: Optional[str] = None

    @field_validator("data_dir", mode="before")
    @classmethod
    def _default_data_dir(cls, v: Optional[Path], info: Any) -> Path:
        if v is not None:
            return Path(v)
        root = info.data.get("project_root", _project_root())
        return Path(root) / "data"

    @field_validator("model_dir", mode="before")
    @classmethod
    def _default_model_dir(cls, v: Optional[Path], info: Any) -> Path:
        if v is not None:
            return Path(v)
        root = info.data.get("project_root", _project_root())
        return Path(root) / "models"

    @property
    def classifier_model_path(self) -> Path:
        assert self.model_dir is not None
        return self.model_dir / "log_classifier.joblib"

    @property
    def synthetic_data_path(self) -> Path:
        assert self.data_dir is not None
        return self.data_dir / "synthetic_logs.csv"

    @property
    def has_llm_key(self) -> bool:
        return bool(self.openai_api_key)


# Singleton accessor
_settings: SentinelSettings | None = None


def get_settings() -> SentinelSettings:
    """Return cached application settings."""
    global _settings  # noqa: PLW0603
    if _settings is None:
        _settings = SentinelSettings()
    return _settings


def reset_settings() -> None:
    """Reset cached settings (useful for testing)."""
    global _settings  # noqa: PLW0603
    _settings = None
