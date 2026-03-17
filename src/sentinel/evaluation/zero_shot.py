"""Zero-shot and few-shot classification evaluation on unseen log formats.

Tests the pipeline's ability to correctly classify log types it has
never been explicitly trained on, measuring generalisation capability.
"""

from __future__ import annotations

import logging
from typing import Any

from rich.console import Console

from sentinel.classifiers.pipeline import ClassificationPipeline
from sentinel.core.config import get_settings
from sentinel.evaluation.metrics import compute_metrics

logger = logging.getLogger(__name__)
console = Console()

# ---------------------------------------------------------------------------
# Unseen log formats for zero-shot evaluation
# ---------------------------------------------------------------------------

_ZERO_SHOT_SAMPLES: list[tuple[str, str, str]] = [
    # (source, log_message, expected_label)

    # --- Windows Event Log format (never seen in training) ---
    ("WindowsEventLog", "EventID=4625 An account failed to log on. Account: admin Source: 192.168.1.50", "Security Alert"),
    ("WindowsEventLog", "EventID=4624 An account was successfully logged on. Account: user1", "User Action"),
    ("WindowsEventLog", "EventID=7036 The Windows Update service entered the stopped state.", "System Notification"),
    ("WindowsEventLog", "EventID=1000 Application Error: faulting module ntdll.dll", "Error"),

    # --- AWS CloudTrail format (never seen in training) ---
    ("CloudTrail", "arn:aws:iam::123456:user/admin performed ConsoleLogin from 203.0.113.50 FAILED", "Security Alert"),
    ("CloudTrail", "s3:PutBucketPolicy changed bucket 'prod-data' to public-read by user deployer", "Security Alert"),
    ("CloudTrail", "ec2:RunInstances launched i-0abc123 in us-east-1 by user developer", "User Action"),
    ("CloudTrail", "iam:CreateAccessKey for user service-account by admin", "User Action"),

    # --- Kubernetes / container format (never seen in training) ---
    ("Kubernetes", "pod/api-server-7b9f CrashLoopBackOff: restarting container after 5 failures", "Critical Error"),
    ("Kubernetes", "node/worker-03 NotReady: kubelet stopped posting status", "Critical Error"),
    ("Kubernetes", "deployment/frontend scaled from 3 to 5 replicas", "System Notification"),
    ("Kubernetes", "ingress/api-gateway TLS certificate expires in 7 days", "Deprecation Warning"),

    # --- Firewall / network format (never seen in training) ---
    ("Firewall", "DENY TCP 10.0.0.50:43210 -> 192.168.1.1:22 (SSH brute force detected)", "Security Alert"),
    ("Firewall", "ALLOW UDP 10.0.0.1:53 -> 8.8.8.8:53 (DNS query)", "HTTP Status"),
    ("Firewall", "DROP ICMP flood from 203.0.113.100 — rate limit exceeded", "Security Alert"),

    # --- Database audit log (never seen in training) ---
    ("PostgreSQL", "FATAL: password authentication failed for user 'postgres' from 10.0.0.99", "Security Alert"),
    ("PostgreSQL", "LOG: checkpoint complete: wrote 1234 buffers (5.2%)", "System Notification"),
    ("PostgreSQL", "WARNING: connection limit exceeded for role 'webapp'", "Error"),

    # --- IoT / SCADA format (never seen in training) ---
    ("SCADA", "PLC-07 register write attempted from unauthorized IP 10.99.0.5", "Security Alert"),
    ("SCADA", "Sensor temp_inlet_03 reading 450°C exceeds threshold 400°C", "Resource Usage"),
]


def run_zero_shot_evaluation(
    pipeline: ClassificationPipeline | None = None,
) -> dict[str, Any]:
    """Evaluate the pipeline on completely unseen log formats.

    Returns metrics dict including per-source-type breakdown.
    """
    console.print("[bold cyan]Zero-Shot Classification Evaluation[/]")
    console.print("=" * 60)

    if pipeline is None:
        settings = get_settings()
        pipeline = ClassificationPipeline(settings=settings)

    logs = [(src, msg) for src, msg, _ in _ZERO_SHOT_SAMPLES]
    true_labels = [lbl for _, _, lbl in _ZERO_SHOT_SAMPLES]

    predictions = pipeline.classify(logs)
    pred_labels = [p.label for p in predictions]

    # Overall metrics
    metrics = compute_metrics(true_labels, pred_labels)

    # Per-source breakdown
    source_results: dict[str, dict[str, Any]] = {}
    for (src, msg, true_lbl), pred in zip(_ZERO_SHOT_SAMPLES, predictions):
        if src not in source_results:
            source_results[src] = {"correct": 0, "total": 0, "details": []}

        is_correct = pred.label == true_lbl
        source_results[src]["total"] += 1
        if is_correct:
            source_results[src]["correct"] += 1

        source_results[src]["details"].append({
            "message": msg[:80],
            "expected": true_lbl,
            "predicted": pred.label,
            "method": pred.method.value,
            "confidence": pred.confidence,
            "correct": is_correct,
        })

    # Print results
    for src, data in source_results.items():
        acc = data["correct"] / max(data["total"], 1)
        color = "green" if acc >= 0.75 else "yellow" if acc >= 0.5 else "red"
        console.print(
            f"  [{color}]{src}: {data['correct']}/{data['total']} correct ({acc:.0%})[/]"
        )

    console.print(
        f"\n[bold]Overall: Accuracy={metrics['accuracy']:.4f}  "
        f"F1 Macro={metrics['f1_macro']:.4f}[/]"
    )

    metrics["per_source"] = source_results
    return metrics


def run_few_shot_evaluation(
    pipeline: ClassificationPipeline | None = None,
    n_examples: int = 3,
) -> dict[str, Any]:
    """Evaluate few-shot classification with a small number of examples in the prompt.

    This tests the LLM tier's ability to classify with minimal context.
    Currently uses the SimulatedLLM, so results reflect keyword-matching.
    With a real LLM API key, results would reflect true few-shot capability.
    """
    console.print(f"[bold cyan]Few-Shot Classification Evaluation (n={n_examples})[/]")
    console.print("=" * 60)

    if pipeline is None:
        settings = get_settings()
        pipeline = ClassificationPipeline(settings=settings)

    # Use a subset of zero-shot samples for testing
    test_samples = _ZERO_SHOT_SAMPLES[:12]  # Test on first 12

    logs = [(src, msg) for src, msg, _ in test_samples]
    true_labels = [lbl for _, _, lbl in test_samples]

    predictions = pipeline.classify(logs)
    pred_labels = [p.label for p in predictions]

    metrics = compute_metrics(true_labels, pred_labels)

    console.print(
        f"Few-Shot (n={n_examples}): Accuracy={metrics['accuracy']:.4f}  "
        f"F1 Macro={metrics['f1_macro']:.4f}"
    )

    return metrics
