"""Benchmark harness: multi-dataset, multi-model evaluation suite."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from sentinel.classifiers.bert import BertClassifier
from sentinel.classifiers.llm import SimulatedLLMClassifier
from sentinel.classifiers.pipeline import ClassificationPipeline
from sentinel.classifiers.regex import RegexClassifier
from sentinel.core.config import get_settings
from sentinel.evaluation.datasets import AVAILABLE_DATASETS, load_dataset
from sentinel.evaluation.metrics import compute_metrics, format_report

logger = logging.getLogger(__name__)
console = Console()


def run_benchmark(datasets: list[str] | None = None) -> dict[str, Any]:
    """Execute the benchmark suite across multiple datasets and approaches.

    Parameters
    ----------
    datasets:
        Dataset names to evaluate. Defaults to all available datasets.

    Returns
    -------
    dict:
        Nested results: {dataset_name: {approach_name: metrics_dict}}.
    """
    console.print("[bold cyan]SENTINEL Benchmark Suite[/]")
    console.print("=" * 70)

    if datasets is None:
        datasets = list(AVAILABLE_DATASETS)

    settings = get_settings()
    all_results: dict[str, dict[str, Any]] = {}

    for ds_name in datasets:
        console.print(f"\n[bold magenta]Dataset: {ds_name}[/]")
        console.print("-" * 50)

        try:
            logs, true_labels = load_dataset(ds_name)
        except Exception as exc:
            console.print(f"[red]Failed to load {ds_name}: {exc}[/]")
            continue

        console.print(f"Loaded {len(logs)} samples")

        # Define approaches
        approaches: dict[str, list | None] = {
            "Regex Only": [RegexClassifier()],
            "BERT Only": [
                BertClassifier(
                    model_name=settings.bert_model_name,
                    classifier_path=settings.classifier_model_path,
                )
            ],
            "LLM (Simulated)": [SimulatedLLMClassifier()],
            "Hybrid (Regex→BERT→LLM)": None,
        }

        dataset_results: dict[str, Any] = {}

        for approach_name, classifiers in approaches.items():
            console.print(f"  [yellow]{approach_name}[/]", end=" ")

            if classifiers is None:
                pipeline = ClassificationPipeline(settings=settings)
            else:
                pipeline = ClassificationPipeline(
                    classifiers=classifiers, settings=settings
                )

            start = time.time()
            predictions = pipeline.classify(logs)
            elapsed = time.time() - start

            pred_labels = [p.label for p in predictions]
            metrics = compute_metrics(true_labels, pred_labels)
            metrics["elapsed_seconds"] = round(elapsed, 2)
            metrics["throughput_logs_per_sec"] = round(
                len(logs) / max(elapsed, 0.001), 1
            )
            metrics["dataset"] = ds_name
            metrics["approach"] = approach_name

            dataset_results[approach_name] = metrics
            console.print(
                f"F1={metrics['f1_macro']:.4f}  Acc={metrics['accuracy']:.4f}  "
                f"({metrics['throughput_logs_per_sec']} logs/s)"
            )

            # Log to MLflow if available
            from sentinel.evaluation.mlflow_tracking import log_benchmark_run
            log_benchmark_run(approach_name, ds_name, metrics)

        all_results[ds_name] = dataset_results

    # --- Save results ---
    output_dir = Path(settings.project_root) / "results" / "benchmarks"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "benchmark_results.json"

    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    console.print(f"\n[bold green]Results saved to: {output_path}[/]")

    # --- Summary table ---
    _print_summary_table(all_results)

    return all_results


def _print_summary_table(results: dict[str, dict[str, Any]]) -> None:
    """Print a rich comparison table across all datasets and approaches."""
    table = Table(
        title="Benchmark Comparison",
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("Dataset", style="magenta", width=15)
    table.add_column("Approach", width=28)
    table.add_column("Accuracy", justify="right", width=10)
    table.add_column("F1 Macro", justify="right", width=10)
    table.add_column("F1 Weighted", justify="right", width=12)
    table.add_column("Throughput", justify="right", width=12)

    for ds_name, approaches in results.items():
        for approach_name, m in approaches.items():
            table.add_row(
                ds_name,
                approach_name,
                f"{m['accuracy']:.4f}",
                f"{m['f1_macro']:.4f}",
                f"{m['f1_weighted']:.4f}",
                f"{m['throughput_logs_per_sec']} logs/s",
            )

    console.print()
    console.print(table)


def run_cross_domain_evaluation() -> dict[str, Any]:
    """Run evaluation specifically for cross-domain generalisation analysis.

    Trains/evaluates on synthetic, then tests on HDFS, BGL, Thunderbird
    to measure transfer performance.
    """
    console.print("[bold cyan]Cross-Domain Generalisation Evaluation[/]")
    console.print("=" * 70)

    settings = get_settings()
    pipeline = ClassificationPipeline(settings=settings)

    cross_domain_results: dict[str, Any] = {}

    for ds_name in ["hdfs", "bgl", "thunderbird"]:
        console.print(f"\n[magenta]Testing on: {ds_name}[/]")
        try:
            logs, true_labels = load_dataset(ds_name)
        except Exception as exc:
            console.print(f"[red]Failed: {exc}[/]")
            continue

        predictions = pipeline.classify(logs)
        pred_labels = [p.label for p in predictions]
        metrics = compute_metrics(true_labels, pred_labels)

        # Track which methods were used
        method_dist = {}
        for p in predictions:
            m = p.method.value
            method_dist[m] = method_dist.get(m, 0) + 1

        metrics["method_distribution"] = method_dist
        cross_domain_results[ds_name] = metrics

        console.print(
            f"  Accuracy={metrics['accuracy']:.4f}  "
            f"F1 Macro={metrics['f1_macro']:.4f}  "
            f"Methods: {method_dist}"
        )

    # Save
    output_dir = Path(settings.project_root) / "results" / "benchmarks"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "cross_domain_results.json"

    with open(output_path, "w") as f:
        json.dump(cross_domain_results, f, indent=2, default=str)

    console.print(f"\n[bold green]Cross-domain results saved to: {output_path}[/]")
    return cross_domain_results
