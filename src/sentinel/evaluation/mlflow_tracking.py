"""MLflow experiment tracking integration for SENTINEL benchmarks and training."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_EXPERIMENT_NAME = "sentinel-log-classification"


def _get_mlflow() -> Any:
    """Import mlflow lazily so it's not a hard dependency."""
    try:
        import mlflow
        return mlflow
    except ImportError:
        logger.warning(
            "mlflow is not installed. Install with: pip install mlflow"
        )
        return None


def init_experiment(
    experiment_name: str = _EXPERIMENT_NAME,
    tracking_uri: str | None = None,
) -> bool:
    """Initialise MLflow experiment. Returns True if successful."""
    mlflow = _get_mlflow()
    if mlflow is None:
        return False

    if tracking_uri:
        mlflow.set_tracking_uri(tracking_uri)

    mlflow.set_experiment(experiment_name)
    logger.info("MLflow experiment: %s", experiment_name)
    return True


def log_benchmark_run(
    approach_name: str,
    dataset_name: str,
    metrics: dict[str, Any],
    params: dict[str, Any] | None = None,
) -> None:
    """Log a single benchmark run to MLflow."""
    mlflow = _get_mlflow()
    if mlflow is None:
        return

    with mlflow.start_run(run_name=f"{approach_name}_{dataset_name}"):
        # Parameters
        mlflow.log_param("approach", approach_name)
        mlflow.log_param("dataset", dataset_name)
        mlflow.log_param("total_samples", metrics.get("total_samples", 0))
        if params:
            for k, v in params.items():
                mlflow.log_param(k, v)

        # Metrics
        for key in [
            "accuracy",
            "precision_macro",
            "recall_macro",
            "f1_macro",
            "f1_weighted",
        ]:
            if key in metrics:
                mlflow.log_metric(key, metrics[key])

        if "elapsed_seconds" in metrics:
            mlflow.log_metric("elapsed_seconds", metrics["elapsed_seconds"])
        if "throughput_logs_per_sec" in metrics:
            mlflow.log_metric(
                "throughput_logs_per_sec", metrics["throughput_logs_per_sec"]
            )

    logger.info("Logged MLflow run: %s on %s", approach_name, dataset_name)


def log_training_run(
    model_name: str,
    metrics: dict[str, Any],
    params: dict[str, Any],
    model_path: Path | None = None,
) -> None:
    """Log a training run with optional model artifact."""
    mlflow = _get_mlflow()
    if mlflow is None:
        return

    with mlflow.start_run(run_name=f"train_{model_name}"):
        for k, v in params.items():
            mlflow.log_param(k, v)

        for k, v in metrics.items():
            if isinstance(v, (int, float)):
                mlflow.log_metric(k, v)

        if model_path and model_path.exists():
            mlflow.log_artifact(str(model_path))

    logger.info("Logged MLflow training run: %s", model_name)


def log_cross_domain_results(results: dict[str, dict[str, Any]]) -> None:
    """Log cross-domain evaluation results."""
    mlflow = _get_mlflow()
    if mlflow is None:
        return

    with mlflow.start_run(run_name="cross_domain_evaluation"):
        for dataset_name, metrics in results.items():
            for key in ["accuracy", "f1_macro", "f1_weighted"]:
                if key in metrics:
                    mlflow.log_metric(f"{dataset_name}_{key}", metrics[key])

    logger.info("Logged cross-domain results to MLflow")
