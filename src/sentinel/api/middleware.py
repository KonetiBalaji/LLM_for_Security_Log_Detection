"""Security middleware: authentication, rate limiting, request size limits."""

from __future__ import annotations

import logging
import time
from collections import defaultdict

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from sentinel.core.config import get_settings

logger = logging.getLogger(__name__)

# Simple in-memory rate limiter (per-IP, resets every window)
_RATE_WINDOW = 60  # seconds
_RATE_LIMIT = 120  # requests per window


class AuthMiddleware(BaseHTTPMiddleware):
    """Bearer token authentication (skipped when auth_enabled=False)."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        settings = get_settings()
        if not settings.auth_enabled:
            return await call_next(request)

        # Allow health endpoints without auth
        if request.url.path in ("/health", "/docs", "/openapi.json", "/"):
            return await call_next(request)

        token = request.headers.get("Authorization", "")
        expected = f"Bearer {settings.auth_token}"
        if token != expected:
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing token"})

        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP rate limiting with sliding window."""

    def __init__(self, app: FastAPI) -> None:
        super().__init__(app)
        self._hits: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - _RATE_WINDOW

        # Clean old entries
        self._hits[client_ip] = [t for t in self._hits[client_ip] if t > window_start]

        if len(self._hits[client_ip]) >= _RATE_LIMIT:
            logger.warning("Rate limit exceeded for %s", client_ip)
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})

        self._hits[client_ip].append(now)
        return await call_next(request)


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests larger than the configured upload limit."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        settings = get_settings()
        max_bytes = settings.max_upload_size_mb * 1024 * 1024

        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > max_bytes:
            return JSONResponse(
                status_code=413,
                content={"detail": f"Request body exceeds {settings.max_upload_size_mb} MB limit"},
            )

        return await call_next(request)
