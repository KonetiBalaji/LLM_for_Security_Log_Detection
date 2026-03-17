# Multi-stage build for SENTINEL
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy project definition first (for layer caching)
COPY pyproject.toml ./
COPY src/ src/

# Install the package
RUN pip install --no-cache-dir ".[dev]"

# --- Runtime stage ---
FROM python:3.11-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY src/ src/
COPY templates/ templates/
COPY data/ data/
COPY models/ models/
COPY pyproject.toml ./

# Non-root user
RUN useradd -m sentinel && chown -R sentinel:sentinel /app
USER sentinel

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "sentinel.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
