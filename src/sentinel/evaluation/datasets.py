"""Dataset loaders for benchmarking."""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

from sentinel.core.config import get_settings

logger = logging.getLogger(__name__)


def load_synthetic_dataset() -> tuple[list[str], list[str]]:
    """Load the built-in synthetic log dataset.

    Returns (log_messages, true_labels).
    """
    settings = get_settings()
    path = settings.synthetic_data_path

    if not path.exists():
        raise FileNotFoundError(f"Synthetic dataset not found at {path}")

    df = pd.read_csv(path)
    required = {"log_message", "target_label"}
    if not required.issubset(df.columns):
        raise ValueError(f"Dataset missing columns: {required - set(df.columns)}")

    return df["log_message"].tolist(), df["target_label"].tolist()


def load_synthetic_with_source() -> tuple[list[tuple[str, str]], list[str]]:
    """Load synthetic dataset as (source, message) tuples with labels."""
    settings = get_settings()
    df = pd.read_csv(settings.synthetic_data_path)

    if "source" not in df.columns:
        df["source"] = "unknown"

    logs = list(zip(df["source"], df["log_message"]))
    labels = df["target_label"].tolist()
    return logs, labels
