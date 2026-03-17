"""File I/O helpers."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd

from sentinel.parsers.registry import detect_log_type, preprocess_logs

logger = logging.getLogger(__name__)


def load_log_file(path: Path | str) -> list[tuple[str, str]]:
    """Load a log file and return ``(source, log_message)`` tuples.

    Supports ``.csv``, ``.log``, and ``.txt`` files.
    """
    path = Path(path)
    source = path.stem

    if path.suffix == ".csv":
        return _load_csv(path, source)
    return _load_text(path, source)


def _load_csv(path: Path, fallback_source: str) -> list[tuple[str, str]]:
    df = pd.read_csv(path)
    if "log_message" not in df.columns:
        raise ValueError(f"CSV {path} missing 'log_message' column")
    if "source" not in df.columns:
        df["source"] = fallback_source
    return list(zip(df["source"], df["log_message"]))


def _load_text(path: Path, source: str) -> list[tuple[str, str]]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [ln.strip() for ln in f if ln.strip()]

    if not lines:
        return []

    log_type = detect_log_type(lines[0])
    df = preprocess_logs(lines, log_type)

    if "log_message" not in df.columns:
        df["log_message"] = df.get("raw", pd.Series(lines))
    if "source" not in df.columns:
        df["source"] = source

    return list(zip(df["source"], df["log_message"]))


def save_json(data: Any, path: Path | str) -> None:
    """Write *data* as JSON to *path*, creating parent dirs as needed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    logger.info("Saved JSON: %s", path)
