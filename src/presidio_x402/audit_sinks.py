"""Enterprise-tier remote audit sinks (v0.6.0).

The base writers in :mod:`presidio_x402.audit_log` (``Null``/``Stream``/``File``)
keep audit records local. Production deployments usually need them in a central
store too — object storage for retention, or a SIEM for alerting. These sinks are
:class:`~presidio_x402._types.AuditWriter` implementations that batch records and
ship them to S3, Splunk HEC, or Datadog Logs.

Design invariants
-----------------
* **Never break the payment path.** ``write()`` only appends to an in-memory
  buffer; the network ship happens in ``flush()`` (or when a batch fills). A ship
  failure is logged and the batch is *retained* for the next flush — it never
  propagates out of ``write()``. (:class:`~presidio_x402.audit_log.AuditLog`
  re-raises writer errors, so a raising remote sink would abort a payment.)
* **Bounded memory.** The retained buffer is capped (``max_buffer``); on overflow
  the oldest records are dropped with an ERROR rather than growing without limit
  (adversary chain-03, audit-OOM). Local durability should be provided by also
  writing to a :class:`~presidio_x402.audit_log.FileAuditWriter` — see
  :class:`MultiAuditWriter`.
* **Injectable transport.** Every sink accepts a pre-built client so deployments
  control TLS/credentials/timeouts and tests need no network. When omitted, the
  client is lazily constructed (``boto3`` for S3 is an optional dependency).

Example::

    from presidio_x402.audit_log import AuditLog, FileAuditWriter
    from presidio_x402.audit_sinks import MultiAuditWriter, S3AuditWriter

    log = AuditLog(writer=MultiAuditWriter(
        FileAuditWriter("/var/log/x402-audit.jsonl"),   # local durability
        S3AuditWriter(bucket="acme-audit", key_prefix="x402/"),  # central retention
    ))
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlparse

from .audit_log import _event_to_dict

if TYPE_CHECKING:
    from ._types import AuditEvent, AuditWriter

logger = logging.getLogger("presidio_x402.audit_sinks")

_DEFAULT_BATCH = 100
_DEFAULT_MAX_BUFFER = 10_000


def _require_https_url(url: str, *, field_name: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError(f"{field_name} must be an https:// URL")


def _require_hostname_component(value: str, *, field_name: str) -> None:
    if not value or any(ch in value for ch in "/:@?#\\"):
        raise ValueError(f"{field_name} must be a hostname, not a URL")
    labels = value.split(".")
    if any(not label or not all(c.isalnum() or c == "-" for c in label) for label in labels):
        raise ValueError(f"{field_name} must be a valid hostname component")


class _HttpClient(Protocol):
    """Minimal structural type for the injectable HTTP transport (httpx-compatible)."""

    def post(self, url: str, **kwargs: Any) -> Any:
        pass


class _BatchingSink:
    """Shared batching/buffering machinery for remote :class:`AuditWriter` sinks.

    Subclasses implement :meth:`_ship`, which must raise on failure; the base turns
    that into a retained-and-logged batch rather than a propagated exception.
    """

    def __init__(self, *, batch_size: int = _DEFAULT_BATCH, max_buffer: int = _DEFAULT_MAX_BUFFER):
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        if max_buffer < batch_size:
            raise ValueError("max_buffer must be >= batch_size")
        self._batch_size = batch_size
        self._max_buffer = max_buffer
        self._buffer: list[dict] = []
        self._lock = threading.Lock()

    # -- AuditWriter interface ------------------------------------------------

    def write(self, event: AuditEvent) -> None:
        flush_now = False
        with self._lock:
            self._buffer.append(_event_to_dict(event))
            if len(self._buffer) >= self._batch_size:
                flush_now = True
        if flush_now:
            self.flush()

    def flush(self) -> None:
        with self._lock:
            if not self._buffer:
                return
            batch = self._buffer
            self._buffer = []
            try:
                self._ship(batch)
            except Exception:
                # Retain the batch for a later flush; never propagate into the
                # payment path. Bound the buffer so a sustained outage cannot OOM.
                logger.exception(
                    "%s: ship failed, retaining %d record(s)", type(self).__name__, len(batch)
                )
                self._buffer = batch + self._buffer
                if len(self._buffer) > self._max_buffer:
                    dropped = len(self._buffer) - self._max_buffer
                    self._buffer = self._buffer[-self._max_buffer :]
                    logger.error(
                        "%s: buffer over %d, dropped %d oldest audit record(s)",
                        type(self).__name__,
                        self._max_buffer,
                        dropped,
                    )

    # -- subclass hook --------------------------------------------------------

    def _ship(self, batch: list[dict]) -> None:  # pragma: no cover - abstract
        raise NotImplementedError


def _jsonl(batch: list[dict]) -> str:
    return "\n".join(json.dumps(d, default=str) for d in batch)


class S3AuditWriter(_BatchingSink):
    """Ships batched audit records to S3 as newline-delimited JSON objects.

    One object per flushed batch, keyed ``<key_prefix><utc-iso>-<uuid>.jsonl``.
    Pass a ``client`` (a boto3 S3 client) to control credentials/region; when
    omitted, ``boto3`` is imported lazily (optional extra ``[audit-s3]``).
    """

    def __init__(
        self,
        bucket: str,
        *,
        key_prefix: str = "x402-audit/",
        client: Any | None = None,
        batch_size: int = _DEFAULT_BATCH,
        max_buffer: int = _DEFAULT_MAX_BUFFER,
    ) -> None:
        super().__init__(batch_size=batch_size, max_buffer=max_buffer)
        self._bucket = bucket
        self._key_prefix = key_prefix
        if client is None:
            try:
                import boto3
            except ImportError as exc:
                raise ImportError(
                    "S3AuditWriter needs boto3: pip install 'presidio-hardened-x402[audit-s3]' "
                    "(or pass an explicit client=)"
                ) from exc
            client = boto3.client("s3")
        self._client = client

    def _ship(self, batch: list[dict]) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S")
        key = f"{self._key_prefix}{ts}-{uuid.uuid4().hex}.jsonl"
        self._client.put_object(Bucket=self._bucket, Key=key, Body=_jsonl(batch).encode("utf-8"))


class SplunkAuditWriter(_BatchingSink):
    """Ships batched audit records to a Splunk HTTP Event Collector (HEC) endpoint.

    ``client`` is an ``httpx.Client`` (injectable for TLS/timeout/tests); when
    omitted one is created lazily. Each record is wrapped as ``{"event": ...}`` per
    HEC, sent newline-delimited in one request per batch.
    """

    def __init__(
        self,
        hec_url: str,
        token: str,
        *,
        client: _HttpClient | None = None,
        batch_size: int = _DEFAULT_BATCH,
        max_buffer: int = _DEFAULT_MAX_BUFFER,
    ) -> None:
        super().__init__(batch_size=batch_size, max_buffer=max_buffer)
        _require_https_url(hec_url, field_name="hec_url")
        self._url = hec_url
        self._headers = {"Authorization": f"Splunk {token}"}
        if client is None:
            import httpx

            client = httpx.Client(timeout=10.0)
        self._client = client

    def _ship(self, batch: list[dict]) -> None:
        body = "\n".join(json.dumps({"event": d}, default=str) for d in batch)
        resp = self._client.post(self._url, content=body, headers=self._headers)
        resp.raise_for_status()


class DatadogAuditWriter(_BatchingSink):
    """Ships batched audit records to the Datadog Logs intake API.

    ``client`` is an ``httpx.Client`` (injectable); ``site`` selects the Datadog
    region (e.g. ``datadoghq.eu``). One JSON-array request per batch.
    """

    def __init__(
        self,
        api_key: str,
        *,
        site: str = "datadoghq.com",
        source: str = "presidio-x402",
        service: str = "x402-audit",
        client: _HttpClient | None = None,
        batch_size: int = _DEFAULT_BATCH,
        max_buffer: int = _DEFAULT_MAX_BUFFER,
    ) -> None:
        super().__init__(batch_size=batch_size, max_buffer=max_buffer)
        _require_hostname_component(site, field_name="site")
        self._url = f"https://http-intake.logs.{site}/api/v2/logs"
        self._headers = {"DD-API-KEY": api_key}
        self._source = source
        self._service = service
        if client is None:
            import httpx

            client = httpx.Client(timeout=10.0)
        self._client = client

    def _ship(self, batch: list[dict]) -> None:
        payload = [
            {
                "ddsource": self._source,
                "service": self._service,
                "message": json.dumps(d, default=str),
            }
            for d in batch
        ]
        resp = self._client.post(self._url, json=payload, headers=self._headers)
        resp.raise_for_status()


class MultiAuditWriter:
    """Fan-out :class:`AuditWriter` — writes each event to several sinks.

    The intended enterprise pattern: a local :class:`FileAuditWriter` for durable,
    fsync-backed capture *and* a remote sink for central retention/alerting. A
    failure in one writer is logged and does not stop the others or the payment.
    """

    def __init__(self, *writers: AuditWriter) -> None:
        if not writers:
            raise ValueError("MultiAuditWriter needs at least one writer")
        self._writers = writers

    def write(self, event: AuditEvent) -> None:
        for w in self._writers:
            try:
                w.write(event)
            except Exception:
                logger.exception("MultiAuditWriter: writer %r failed", type(w).__name__)

    def flush(self) -> None:
        for w in self._writers:
            try:
                flush = getattr(w, "flush", None)
                if callable(flush):
                    flush()
            except Exception:
                logger.exception("MultiAuditWriter: flush of %r failed", type(w).__name__)
