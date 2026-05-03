"""presidio-hardened-x402 sidecar — FastAPI health and metrics endpoint.

Exposes:
  GET /health  — liveness probe (200 OK)
  GET /metrics — Prometheus metrics (text/plain; version=0.0.4)
  GET /version — package version

Environment variables:
  X402_AGENT_ID          — agent identifier for audit events
  X402_MAX_PER_CALL_USD  — per-call payment limit (USD)
  X402_DAILY_LIMIT_USD   — daily aggregate spend limit (USD)
  X402_REDIS_URL         — Redis URL for cross-process replay guard
"""

from __future__ import annotations

import os

from fastapi import FastAPI
from starlette.responses import JSONResponse, PlainTextResponse

import presidio_x402
from presidio_x402.metrics import _PROM_AVAILABLE, MetricsCollector

app = FastAPI(
    title="presidio-hardened-x402 sidecar",
    version=presidio_x402.__version__,
    docs_url=None,
    redoc_url=None,
)

# Constructed for its prometheus-collector registration side-effect; the
# instance itself is parked on app.state so module-level attribute reads
# keep it from looking unused to static analysers.
app.state.metrics_collector = MetricsCollector()


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse(
        {
            "status": "ok",
            "version": presidio_x402.__version__,
            "agent_id": os.getenv("X402_AGENT_ID", ""),
        }
    )


@app.get("/version")
async def version() -> JSONResponse:
    return JSONResponse({"version": presidio_x402.__version__})


@app.get("/metrics")
async def metrics() -> PlainTextResponse:
    if not _PROM_AVAILABLE:
        return PlainTextResponse(
            "# prometheus-client not installed\n",
            media_type="text/plain",
        )
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

    return PlainTextResponse(
        generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
