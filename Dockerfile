# syntax=docker/dockerfile:1
#
# AdGuard Rules Merger v8.0.1 — multi-stage image.
#
# Build:  docker build -t adguard-rules-merger:8.0.1 .
# Run:    docker run --rm -v "$PWD/output:/app/output" \
#                       -v "$PWD/cache:/app/cache" \
#                       adguard-rules-merger:8.0.1 merge --config config/sources.yaml
#
# The final image ships a pre-built virtual environment and the package
# installed with its console script; no build tooling is present at runtime.

FROM python:3.12-slim AS builder

# uv is a single static binary — copy it from the official image.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml uv.lock ./
COPY merger ./merger
COPY merge_rules.py config_loader.py README.md ./
COPY config ./config

# Build the virtual environment with the project installed (no dev deps).
RUN uv sync --frozen --no-install-project --no-dev \
 && uv sync --frozen --no-dev \
 && uv pip install --no-deps .

# ── Runtime ───────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

WORKDIR /app

# Non-root user.
RUN useradd --create-home --uid 10001 appuser

COPY --from=builder /app/.venv /app/.venv
COPY --chown=appuser:appuser merger ./merger
COPY --chown=appuser:appuser merge_rules.py config_loader.py pyproject.toml ./
COPY --chown=appuser:appuser config ./config

# Output/cache are volume mounts; ensure they exist and are writable.
RUN mkdir -p /app/output /app/cache && chown -R appuser:appuser /app
USER appuser

VOLUME ["/app/output", "/app/cache"]

ENTRYPOINT ["adguard-rules-merger"]
CMD ["--help"]
