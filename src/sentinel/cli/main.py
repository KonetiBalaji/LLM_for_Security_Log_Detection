"""SENTINEL CLI — analyse logs, serve API, run benchmarks."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()
logger = logging.getLogger(__name__)


def run() -> None:
    """Entry-point for ``sentinel`` command."""
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="SENTINEL — AI-driven security log analysis",
    )
    sub = parser.add_subparsers(dest="command")

    # --- analyse ---
    p_analyse = sub.add_parser("analyze", help="Analyse log files")
    p_analyse.add_argument("input", help="Log file or directory path")
    p_analyse.add_argument("-o", "--output", default="results", help="Output directory")
    p_analyse.add_argument("-r", "--recursive", action="store_true")

    # --- serve ---
    p_serve = sub.add_parser("serve", help="Start the API server")
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8000)

    # --- benchmark ---
    sub.add_parser("benchmark", help="Run evaluation benchmarks")

    # --- train ---
    sub.add_parser("train", help="Train the BERT classifier")

    args = parser.parse_args()

    if args.command == "analyze":
        _cmd_analyze(args.input, args.output, args.recursive)
    elif args.command == "serve":
        _cmd_serve(args.host, args.port)
    elif args.command == "benchmark":
        _cmd_benchmark()
    elif args.command == "train":
        _cmd_train()
    else:
        parser.print_help()


def _cmd_analyze(input_path: str, output_dir: str, recursive: bool) -> None:
    from sentinel.analyzers.orchestrator import SecurityAnalyzer
    from sentinel.classifiers.pipeline import ClassificationPipeline
    from sentinel.parsers.registry import detect_log_type, preprocess_logs
    from sentinel.utils.io import load_log_file, save_json

    pipeline = ClassificationPipeline()
    analyzer = SecurityAnalyzer()

    path = Path(input_path)
    if path.is_file():
        files = [path]
    elif path.is_dir():
        pattern = "**/*" if recursive else "*"
        files = [f for f in path.glob(pattern) if f.suffix in (".log", ".txt", ".csv")]
    else:
        console.print(f"[bold red]Path not found: {input_path}[/]")
        sys.exit(1)

    if not files:
        console.print("[bold red]No log files found.[/]")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    for file_path in files:
        console.print(f"[cyan]Processing: {file_path}[/]")
        with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"), console=console) as progress:
            progress.add_task("Loading…")
            logs = load_log_file(file_path)
            if not logs:
                console.print(f"[yellow]Skipping empty file: {file_path}[/]")
                continue

            progress.add_task("Classifying…")
            results = pipeline.classify(logs)

            progress.add_task("Analysing…")
            analysis = analyzer.analyze(results)

        _print_analysis(analysis)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = Path(output_dir) / f"{file_path.stem}_analysis_{ts}.json"
        save_json(analysis.to_dict(), out_path)
        console.print(f"[green]Saved: {out_path}[/]")

    console.print("[bold green]Processing complete.[/]")


def _cmd_serve(host: str, port: int) -> None:
    import uvicorn
    console.print(f"[cyan]Starting SENTINEL API on {host}:{port}[/]")
    uvicorn.run("sentinel.api.app:app", host=host, port=port, reload=True)


def _cmd_benchmark() -> None:
    from sentinel.evaluation.benchmark import run_benchmark
    run_benchmark()


def _cmd_train() -> None:
    from sentinel.evaluation.train import train_bert_classifier
    train_bert_classifier()


def _print_analysis(analysis: Any) -> None:
    """Pretty-print analysis results."""
    result = analysis.to_dict() if hasattr(analysis, "to_dict") else analysis

    console.print(Panel.fit(
        f"[bold yellow]SENTINEL Security Analysis Report[/]\n"
        f"[blue]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]",
        border_style="yellow",
    ))

    summary = result.get("summary", "No summary available.")
    attention = result.get("requires_immediate_attention", False)
    color = "red" if attention else "green"
    console.print(Panel(
        f"[white]{summary}[/]\n"
        f"[bold {color}]Requires Immediate Attention: {attention}[/]",
        border_style="blue",
    ))

    events = result.get("events", [])
    if events:
        table = Table(show_header=True, header_style="bold red", show_lines=True)
        table.add_column("Type", width=22)
        table.add_column("Severity", width=10)
        table.add_column("Attack", width=20)
        table.add_column("MITRE", width=12)
        table.add_column("Recommendation", width=40)
        for ev in events:
            mitre = ev.get("mitre_technique", {})
            mitre_id = mitre.get("technique_id", "—") if mitre else "—"
            table.add_row(
                ev.get("event_type", ""),
                ev.get("severity", ""),
                ev.get("attack_type", ""),
                mitre_id,
                (ev.get("recommendation") or "—")[:80],
            )
        console.print(table)


if __name__ == "__main__":
    run()
