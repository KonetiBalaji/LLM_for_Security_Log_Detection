"""Full security analysis API routes."""

from __future__ import annotations

import logging
import os
import tempfile
from typing import Any

import pandas as pd
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from sentinel.analyzers.orchestrator import SecurityAnalyzer
from sentinel.api.dependencies import get_analyzer, get_pipeline
from sentinel.classifiers.pipeline import ClassificationPipeline
from sentinel.parsers.registry import detect_log_type, preprocess_logs

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["analyze"])

_ALLOWED_EXTENSIONS = {".csv", ".log", ".txt"}
_MAX_FILE_BYTES = 50 * 1024 * 1024


@router.post("/analyze")
async def analyze_file(
    file: UploadFile = File(...),
    pipeline: ClassificationPipeline = Depends(get_pipeline),
    analyzer: SecurityAnalyzer = Depends(get_analyzer),
) -> JSONResponse:
    """Upload a log file and receive full security analysis."""

    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {ext}")

    temp_path: str | None = None

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
            temp_path = tmp.name
            content = await file.read()
            if len(content) > _MAX_FILE_BYTES:
                raise HTTPException(status_code=413, detail="File too large (max 50 MB)")
            tmp.write(content)

        logs = _load_logs(temp_path, file.filename)
        classified = pipeline.classify(logs)
        result = analyzer.analyze(classified)

        return JSONResponse(content=result.to_dict())

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Analysis error")
        raise HTTPException(status_code=500, detail=f"Analysis error: {exc}") from exc
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


@router.post("/analyze/raw")
async def analyze_raw_logs(
    logs: str = Form(...),
    log_format: str | None = Form(default=None),
    pipeline: ClassificationPipeline = Depends(get_pipeline),
    analyzer: SecurityAnalyzer = Depends(get_analyzer),
) -> JSONResponse:
    """Analyse raw log text pasted by the user."""

    lines = [ln.strip() for ln in logs.strip().split("\n") if ln.strip()]
    if not lines:
        raise HTTPException(status_code=400, detail="No log lines provided")

    if len(lines) > 10_000:
        raise HTTPException(status_code=400, detail="Maximum 10,000 lines per request")

    try:
        log_type = detect_log_type(lines[0])
        df = preprocess_logs(lines, log_type)

        if "log_message" not in df.columns:
            df["log_message"] = df.get("raw", pd.Series(lines))
        if "source" not in df.columns:
            df["source"] = "raw_input"

        log_tuples = list(zip(df["source"], df["log_message"]))
        classified = pipeline.classify(log_tuples)
        result = analyzer.analyze(classified)

        response = result.to_dict()
        response["log_info"] = {
            "detected_type": log_type.value if hasattr(log_type, "value") else str(log_type),
            "total_logs": len(lines),
        }

        return JSONResponse(content=response)

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Raw log analysis error")
        raise HTTPException(status_code=500, detail=f"Analysis error: {exc}") from exc


def _load_logs(path: str, filename: str) -> list[tuple[str, str]]:
    source = os.path.splitext(os.path.basename(filename))[0]

    if filename.endswith(".csv"):
        df = pd.read_csv(path)
        if "log_message" not in df.columns:
            raise HTTPException(status_code=400, detail="CSV must have 'log_message' column")
        if "source" not in df.columns:
            df["source"] = source
        return list(zip(df["source"], df["log_message"]))

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [ln.strip() for ln in f if ln.strip()]

    if not lines:
        raise HTTPException(status_code=400, detail="File contains no log entries")

    log_type = detect_log_type(lines[0])
    df = preprocess_logs(lines, log_type)

    if "log_message" not in df.columns:
        df["log_message"] = df.get("raw", pd.Series(lines))
    if "source" not in df.columns:
        df["source"] = source

    return list(zip(df["source"], df["log_message"]))
