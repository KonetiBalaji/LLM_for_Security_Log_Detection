"""Classification API routes."""

from __future__ import annotations

import logging
import os
import tempfile
from typing import Any

import pandas as pd
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

from sentinel.api.dependencies import get_pipeline
from sentinel.classifiers.pipeline import ClassificationPipeline
from sentinel.parsers.registry import detect_log_type, preprocess_logs

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["classify"])

_ALLOWED_EXTENSIONS = {".csv", ".log", ".txt"}
_MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MB


@router.post("/classify")
async def classify_file(
    file: UploadFile = File(...),
    pipeline: ClassificationPipeline = Depends(get_pipeline),
) -> FileResponse:
    """Upload a log file and receive a classified CSV."""

    _validate_upload(file)

    temp_path: str | None = None
    output_path: str | None = None

    try:
        # Save uploaded file to temp
        suffix = os.path.splitext(file.filename or ".csv")[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            temp_path = tmp.name
            content = await file.read()
            if len(content) > _MAX_FILE_BYTES:
                raise HTTPException(status_code=413, detail="File too large (max 50 MB)")
            tmp.write(content)

        # Prepare log data
        logs = _load_logs(temp_path, file.filename or "unknown")

        # Classify
        results = pipeline.classify(logs)

        # Write output
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as out_tmp:
            output_path = out_tmp.name
        df = pd.DataFrame([r.to_dict() for r in results])
        df.to_csv(output_path, index=False)

        return FileResponse(
            output_path,
            media_type="text/csv",
            filename="classified_logs.csv",
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Classification error")
        raise HTTPException(status_code=500, detail=f"Classification error: {exc}") from exc
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _validate_upload(file: UploadFile) -> None:
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {_ALLOWED_EXTENSIONS}",
        )


def _load_logs(path: str, filename: str) -> list[tuple[str, str]]:
    """Load logs from file and return (source, message) tuples."""
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
