"""Feedback API routes for analyst-in-the-loop corrections."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from sentinel.feedback.feedback_store import FeedbackEntry, FeedbackStore

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/feedback", tags=["feedback"])

_store = FeedbackStore()


class FeedbackRequest(BaseModel):
    """Request body for submitting analyst feedback."""

    log_message: str
    predicted_label: str
    predicted_confidence: float = 0.0
    predicted_method: str = ""
    is_correct: bool
    correct_label: str | None = None
    analyst_id: str = ""
    notes: str = ""


class FeedbackResponse(BaseModel):
    """Response after submitting feedback."""

    id: str
    message: str


@router.post("", response_model=FeedbackResponse)
async def submit_feedback(req: FeedbackRequest) -> FeedbackResponse:
    """Submit analyst feedback on a classification result."""
    if not req.is_correct and not req.correct_label:
        raise HTTPException(
            status_code=400,
            detail="correct_label is required when is_correct=false",
        )

    entry = FeedbackEntry(
        log_message=req.log_message,
        predicted_label=req.predicted_label,
        predicted_confidence=req.predicted_confidence,
        predicted_method=req.predicted_method,
        is_correct=req.is_correct,
        correct_label=req.correct_label,
        analyst_id=req.analyst_id,
        notes=req.notes,
    )

    entry_id = _store.submit(entry)
    return FeedbackResponse(id=entry_id, message="Feedback recorded")


@router.get("/stats")
async def get_feedback_stats() -> dict:
    """Return summary statistics of collected feedback."""
    return _store.get_stats()


@router.get("/corrections")
async def get_corrections() -> list[dict]:
    """Return all analyst corrections for retraining."""
    from dataclasses import asdict
    corrections = _store.get_corrections()
    return [asdict(c) for c in corrections]
