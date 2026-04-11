# presidio-hardened-x402 sidecar container
# Exposes a health endpoint and Prometheus /metrics for the security controls.
#
# Build:
#   docker build -f docker/Dockerfile -t ghcr.io/presidio-v/presidio-hardened-x402:0.3.0 .
#
# Run:
#   docker run -p 8080:8080 \
#     -e X402_AGENT_ID=my-agent \
#     -e X402_MAX_PER_CALL_USD=0.10 \
#     -e X402_DAILY_LIMIT_USD=5.0 \
#     ghcr.io/presidio-v/presidio-hardened-x402:0.3.0

# ── Stage 1: build ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir uv && \
    uv pip install --system --no-cache \
        ".[prometheus]" \
        "fastapi>=0.111.0" \
        "uvicorn[standard]>=0.29.0"

# Download spaCy model for NLP mode (optional; comment out for regex-only images)
RUN python -m spacy download en_core_web_sm --quiet

# ── Stage 2: runtime ────────────────────────────────────────────────────────
FROM python:3.12-slim

# Non-root user for least-privilege execution
RUN groupadd --gid 1001 x402 && \
    useradd --uid 1001 --gid x402 --shell /bin/false --no-create-home x402

WORKDIR /app

# Copy installed packages and entrypoint from builder
COPY --from=builder /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy sidecar application
COPY docker/sidecar_app.py .

USER x402
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

CMD ["uvicorn", "sidecar_app:app", "--host", "0.0.0.0", "--port", "8080"]
