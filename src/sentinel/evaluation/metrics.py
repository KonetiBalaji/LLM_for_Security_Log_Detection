"""Evaluation metrics for classification benchmarks."""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


def compute_metrics(y_true: list[str], y_pred: list[str]) -> dict[str, Any]:
    """Compute a full metrics dictionary from true and predicted labels."""
    labels = sorted(set(y_true) | set(y_pred))

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "classification_report": classification_report(
            y_true, y_pred, labels=labels, zero_division=0, output_dict=True
        ),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "labels": labels,
        "total_samples": len(y_true),
    }


def format_report(metrics: dict[str, Any]) -> str:
    """Format metrics dict into a human-readable string."""
    lines = [
        "=" * 60,
        "BENCHMARK RESULTS",
        "=" * 60,
        f"Total samples: {metrics['total_samples']}",
        f"Accuracy:      {metrics['accuracy']:.4f}",
        f"Precision:     {metrics['precision_macro']:.4f} (macro)",
        f"Recall:        {metrics['recall_macro']:.4f} (macro)",
        f"F1 Score:      {metrics['f1_macro']:.4f} (macro)",
        f"F1 Weighted:   {metrics['f1_weighted']:.4f}",
        "",
        "Per-class report:",
        classification_report(
            ["_placeholder"], ["_placeholder"],
        ) if False else "",
    ]
    # Use sklearn's built-in text report
    report = metrics.get("classification_report", {})
    for label in metrics.get("labels", []):
        if label in report:
            p = report[label]
            lines.append(
                f"  {label:<30} P={p['precision']:.3f}  R={p['recall']:.3f}  "
                f"F1={p['f1-score']:.3f}  n={int(p['support'])}"
            )
    lines.append("=" * 60)
    return "\n".join(lines)
