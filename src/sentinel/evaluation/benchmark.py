"""Benchmark harness: run classification pipeline against datasets and report metrics."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from rich.console import Console

from sentinel.classifiers.bert import BertClassifier
from sentinel.classifiers.llm import SimulatedLLMClassifier
from sentinel.classifiers.pipeline import ClassificationPipeline
from sentinel.classifiers.regex import RegexClassifier
from sentinel.core.config import get_settings
from sentinel.evaluation.datasets import load_synthetic_with_source
from sentinel.evaluation.metrics import compute_metrics, format_report

logger = logging.getLogger(__name__)
console = Console()


def run_benchmark() -> None:
    """Execute the full benchmark suite and print results."""
    console.print("[bold cyan]SENTINEL Benchmark Suite[/]")
    console.print("=" * 60)

    logs, true_labels = load_synthetic_with_source()
    console.print(f"Dataset: synthetic ({len(logs)} samples)")
    console.print()

    settings = get_settings()

    # --- Define approaches to compare ---
    approaches: dict[str, list] = {
        "Regex Only": [RegexClassifier()],
        "BERT Only": [
            BertClassifier(
                model_name=settings.bert_model_name,
                classifier_path=settings.classifier_model_path,
            )
        ],
        "LLM (Simulated)": [SimulatedLLMClassifier()],
        "Hybrid (Regex→BERT→LLM)": None,  # uses default pipeline
    }

    all_results: dict[str, dict] = {}

    for name, classifiers in approaches.items():
        console.print(f"[bold yellow]Running: {name}[/]")

        if classifiers is None:
            pipeline = ClassificationPipeline(settings=settings)
        else:
            pipeline = ClassificationPipeline(classifiers=classifiers, settings=settings)

        start = time.time()
        predictions = pipeline.classify(logs)
        elapsed = time.time() - start

        pred_labels = [p.label for p in predictions]
        metrics = compute_metrics(true_labels, pred_labels)
        metrics["elapsed_seconds"] = round(elapsed, 2)
        metrics["throughput_logs_per_sec"] = round(len(logs) / max(elapsed, 0.001), 1)

        all_results[name] = metrics
        console.print(format_report(metrics))
        console.print(f"  Time: {elapsed:.2f}s  ({metrics['throughput_logs_per_sec']} logs/s)")
        console.print()

    # --- Save results ---
    output_dir = Path(settings.project_root) / "results" / "benchmarks"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "benchmark_results.json"

    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    console.print(f"[bold green]Results saved to: {output_path}[/]")

    # --- Comparison table ---
    console.print()
    console.print("[bold cyan]Comparison Summary[/]")
    header = f"{'Approach':<30} {'Accuracy':>10} {'F1 Macro':>10} {'F1 Weighted':>12} {'Time':>8}"
    console.print(header)
    console.print("-" * len(header))
    for name, m in all_results.items():
        console.print(
            f"{name:<30} {m['accuracy']:>10.4f} {m['f1_macro']:>10.4f} "
            f"{m['f1_weighted']:>12.4f} {m['elapsed_seconds']:>7.2f}s"
        )
