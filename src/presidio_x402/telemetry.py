"""Optional OpenTelemetry helpers for presidio_x402 security controls."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any


class _NoopSpan:
    def set_attribute(self, key: str, value: object) -> None:
        return


_NOOP_SPAN = _NoopSpan()


def _trace_api() -> Any | None:
    try:
        from opentelemetry import trace
    except ImportError:
        return None
    return trace


def _tracer() -> Any | None:
    trace = _trace_api()
    if trace is None:
        return None
    provider = trace.get_tracer_provider()
    if provider.__class__.__name__ in {"NoOpTracerProvider", "ProxyTracerProvider"}:
        return None
    return trace.get_tracer("presidio_x402")


def _attribute_value(value: object) -> object | None:
    if isinstance(value, str | bool | int | float):
        return value
    if isinstance(value, tuple | list) and all(
        isinstance(v, str | bool | int | float) for v in value
    ):
        return list(value)
    return None


def set_span_attribute(span: Any, key: str, value: object) -> None:
    attr = _attribute_value(value)
    if attr is not None:
        span.set_attribute(key, attr)


@contextmanager
def security_control_span(control: str, **attributes: object):
    """Return a span context for a security control, or a near-zero no-op.

    Spans are emitted only when ``opentelemetry-api`` is installed and a real
    tracer provider has been configured by the host application. With no
    provider, or without the optional ``[otel]`` extra, this returns a null
    context carrying a span-like no-op object.
    """
    tracer = _tracer()
    if tracer is None:
        yield _NOOP_SPAN
        return
    with tracer.start_as_current_span(f"presidio_x402.security.{control}") as span:
        set_span_attribute(span, "presidio_x402.control", control)
        for key, value in attributes.items():
            set_span_attribute(span, f"presidio_x402.{key}", value)
        yield span
