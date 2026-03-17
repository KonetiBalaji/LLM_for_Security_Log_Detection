"""Dataset loaders for benchmarking: synthetic, HDFS, BGL, Thunderbird."""

from __future__ import annotations

import csv
import io
import logging
import os
import re
import zipfile
from pathlib import Path
from typing import Any
from urllib.request import urlretrieve

import pandas as pd

from sentinel.core.config import get_settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Synthetic dataset (bundled)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# HDFS dataset (Loghub)
# ---------------------------------------------------------------------------

_HDFS_URL = "https://raw.githubusercontent.com/logpai/loghub/master/HDFS/HDFS_2k.log"
_HDFS_LABELS_URL = "https://raw.githubusercontent.com/logpai/loghub/master/HDFS/anomaly_label.csv"

# HDFS log-level → simplified label mapping
_HDFS_LEVEL_MAP = {
    "INFO": "System Notification",
    "WARN": "Error",
    "WARNING": "Error",
    "ERROR": "Critical Error",
    "FATAL": "Critical Error",
}

_HDFS_LINE_RE = re.compile(
    r"(\d{6})\s+(\d{6})\s+(\d+)\s+(INFO|WARN|WARNING|ERROR|FATAL)\s+(.+)"
)


def download_hdfs(dest_dir: Path | None = None) -> Path:
    """Download HDFS 2k sample log to the data directory."""
    settings = get_settings()
    dest_dir = dest_dir or (settings.data_dir / "hdfs")  # type: ignore[operator]
    dest_dir.mkdir(parents=True, exist_ok=True)

    log_path = dest_dir / "HDFS_2k.log"
    if not log_path.exists():
        logger.info("Downloading HDFS dataset...")
        urlretrieve(_HDFS_URL, log_path)
        logger.info("Saved to %s", log_path)
    return log_path


def load_hdfs_dataset(
    path: Path | None = None,
) -> tuple[list[tuple[str, str]], list[str]]:
    """Load HDFS log dataset with auto-generated labels from log levels.

    Returns ([(source, message)], [label]).
    """
    if path is None:
        path = download_hdfs()

    logs: list[tuple[str, str]] = []
    labels: list[str] = []

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            match = _HDFS_LINE_RE.match(line)
            if match:
                level = match.group(4)
                label = _HDFS_LEVEL_MAP.get(level, "System Notification")
                logs.append(("HDFS", line))
                labels.append(label)
            else:
                logs.append(("HDFS", line))
                labels.append("System Notification")

    logger.info("Loaded HDFS dataset: %d entries", len(logs))
    return logs, labels


# ---------------------------------------------------------------------------
# BGL (Blue Gene/L) dataset
# ---------------------------------------------------------------------------

_BGL_URL = "https://raw.githubusercontent.com/logpai/loghub/master/BGL/BGL_2k.log"

_BGL_LINE_RE = re.compile(
    r"^(-|[A-Z]+)\s+"  # label (- = normal, else alert code)
    r"(\d+)\s+"          # timestamp
    r"\S+\s+"            # date
    r"\S+\s+"            # node
    r"\S+\s+"            # time
    r"\S+\s+"            # node_repeat
    r"(\S+)\s+"          # component
    r"(\S+)\s+"          # level
    r"(.*)"              # message
)


def download_bgl(dest_dir: Path | None = None) -> Path:
    """Download BGL 2k sample log."""
    settings = get_settings()
    dest_dir = dest_dir or (settings.data_dir / "bgl")  # type: ignore[operator]
    dest_dir.mkdir(parents=True, exist_ok=True)

    log_path = dest_dir / "BGL_2k.log"
    if not log_path.exists():
        logger.info("Downloading BGL dataset...")
        urlretrieve(_BGL_URL, log_path)
        logger.info("Saved to %s", log_path)
    return log_path


def load_bgl_dataset(
    path: Path | None = None,
) -> tuple[list[tuple[str, str]], list[str]]:
    """Load BGL dataset. Lines starting with '-' are normal; others are alerts."""
    if path is None:
        path = download_bgl()

    logs: list[tuple[str, str]] = []
    labels: list[str] = []

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("- ") or line.startswith("-\t"):
                logs.append(("BGL", line[2:].strip()))
                labels.append("System Notification")
            else:
                # Alert line — label is the first token
                logs.append(("BGL", line))
                labels.append("Security Alert")

    logger.info("Loaded BGL dataset: %d entries", len(logs))
    return logs, labels


# ---------------------------------------------------------------------------
# Thunderbird dataset
# ---------------------------------------------------------------------------

_THUNDERBIRD_URL = (
    "https://raw.githubusercontent.com/logpai/loghub/master/Thunderbird/Thunderbird_2k.log"
)

_TB_LINE_RE = re.compile(
    r"^(-|[A-Z]+)\s+"  # label
    r"(\d+)\s+"          # id
    r"(\S+)\s+"          # date
    r"(\S+)\s+"          # admin
    r"(\S+)\s+"          # month/day
    r"(\S+)\s+"          # time
    r"(\S+)\s+"          # host
    r"(\S+)\s+"          # component
    r"(.*)"              # message content
)


def download_thunderbird(dest_dir: Path | None = None) -> Path:
    """Download Thunderbird 2k sample log."""
    settings = get_settings()
    dest_dir = dest_dir or (settings.data_dir / "thunderbird")  # type: ignore[operator]
    dest_dir.mkdir(parents=True, exist_ok=True)

    log_path = dest_dir / "Thunderbird_2k.log"
    if not log_path.exists():
        logger.info("Downloading Thunderbird dataset...")
        urlretrieve(_THUNDERBIRD_URL, log_path)
        logger.info("Saved to %s", log_path)
    return log_path


def load_thunderbird_dataset(
    path: Path | None = None,
) -> tuple[list[tuple[str, str]], list[str]]:
    """Load Thunderbird dataset. Lines starting with '-' are normal."""
    if path is None:
        path = download_thunderbird()

    logs: list[tuple[str, str]] = []
    labels: list[str] = []

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("- ") or line.startswith("-\t"):
                logs.append(("Thunderbird", line[2:].strip()))
                labels.append("System Notification")
            else:
                logs.append(("Thunderbird", line))
                labels.append("Security Alert")

    logger.info("Loaded Thunderbird dataset: %d entries", len(logs))
    return logs, labels


# ---------------------------------------------------------------------------
# Unified loader
# ---------------------------------------------------------------------------

AVAILABLE_DATASETS = {
    "synthetic": load_synthetic_with_source,
    "hdfs": load_hdfs_dataset,
    "bgl": load_bgl_dataset,
    "thunderbird": load_thunderbird_dataset,
}


def load_dataset(name: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Load a dataset by name. Downloads if not present."""
    loader = AVAILABLE_DATASETS.get(name.lower())
    if loader is None:
        raise ValueError(
            f"Unknown dataset '{name}'. Available: {list(AVAILABLE_DATASETS)}"
        )
    return loader()
