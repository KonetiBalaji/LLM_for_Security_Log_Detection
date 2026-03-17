"""Train the BERT-based log classifier."""

from __future__ import annotations

import logging

import joblib
import numpy as np
import pandas as pd
from rich.console import Console
from sentence_transformers import SentenceTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

from sentinel.core.config import get_settings

logger = logging.getLogger(__name__)
console = Console()


def train_bert_classifier() -> None:
    """Train a logistic regression classifier on BERT embeddings with cross-validation."""
    settings = get_settings()
    data_path = settings.synthetic_data_path
    output_path = settings.classifier_model_path

    console.print(f"[cyan]Loading data from: {data_path}[/]")
    df = pd.read_csv(data_path)

    required = {"log_message", "target_label"}
    if not required.issubset(df.columns):
        missing = required - set(df.columns)
        raise ValueError(f"Missing columns: {missing}")

    X_text = df["log_message"].values
    y = df["target_label"].values

    console.print(f"[cyan]Loading SentenceTransformer: {settings.bert_model_name}[/]")
    encoder = SentenceTransformer(settings.bert_model_name)

    console.print("[cyan]Generating embeddings…[/]")
    X_embeddings = encoder.encode(X_text, show_progress_bar=True)

    # --- Cross-validation ---
    console.print("[cyan]Running 5-fold stratified cross-validation…[/]")
    clf = LogisticRegression(max_iter=1000, random_state=42)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(clf, X_embeddings, y, cv=cv, scoring="f1_macro")
    console.print(f"CV F1 Macro: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # --- Train / test split for final report ---
    X_train, X_test, y_train, y_test = train_test_split(
        X_embeddings, y, test_size=0.2, random_state=42, stratify=y
    )

    console.print("[cyan]Training final classifier…[/]")
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    console.print("\n[bold]Classification Report:[/]")
    console.print(classification_report(y_test, y_pred))

    # --- Save ---
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, output_path)
    console.print(f"[bold green]Model saved to: {output_path}[/]")


if __name__ == "__main__":
    train_bert_classifier()
