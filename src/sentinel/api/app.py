"""FastAPI application factory."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from starlette.responses import HTMLResponse

from sentinel import __version__
from sentinel.api.middleware import (
    AuthMiddleware,
    RateLimitMiddleware,
    RequestSizeLimitMiddleware,
)
from sentinel.api.routes import analyze, classify, health
from sentinel.core.config import SentinelSettings, get_settings

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "templates"


def create_app(settings: SentinelSettings | None = None) -> FastAPI:
    """Build and configure the FastAPI application."""
    settings = settings or get_settings()

    app = FastAPI(
        title="SENTINEL — Security Log Intelligence Platform",
        description="AI-driven cybersecurity log classification, analysis, and threat detection.",
        version=__version__,
    )

    # --- Middleware (applied in reverse registration order) ---
    app.add_middleware(RequestSizeLimitMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(AuthMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- Routes ---
    app.include_router(health.router)
    app.include_router(classify.router)
    app.include_router(analyze.router)

    # --- Templates / static ---
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    @app.get("/", response_class=HTMLResponse)
    async def homepage(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("index.html", {"request": request})

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    logger.info("SENTINEL v%s starting", __version__)
    return app


# For ``uvicorn sentinel.api.app:app``
app = create_app()
