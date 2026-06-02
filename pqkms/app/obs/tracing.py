# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Optional OpenTelemetry tracing.

Disabled by default and entirely dependency-optional: setup_tracing() is a no-op
unless PQKMS_OTEL_ENABLED is truthy AND the opentelemetry packages are installed.
This keeps the base image lean while letting operators turn on distributed
tracing (exporting to an OTLP collector via the standard OTEL_EXPORTER_OTLP_*
environment variables) without any code change.

To enable:
    pip install opentelemetry-sdk opentelemetry-exporter-otlp \
                opentelemetry-instrumentation-fastapi
    PQKMS_OTEL_ENABLED=1 OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4317 ...
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("pqkms.tracing")


def _truthy(val: "str | None") -> bool:
    return bool(val) and val.strip().lower() not in ("0", "false", "no", "off", "")


def setup_tracing(app) -> bool:
    """Instrument the FastAPI app if tracing is enabled and available. Returns
    True if tracing was activated, False otherwise. Never raises — a tracing
    misconfiguration must not take down the KMS."""
    if not _truthy(os.environ.get("PQKMS_OTEL_ENABLED")):
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError:
        log.warning(
            "PQKMS_OTEL_ENABLED is set but the opentelemetry packages are not "
            "installed; tracing is disabled. Install opentelemetry-sdk, "
            "opentelemetry-exporter-otlp and opentelemetry-instrumentation-fastapi."
        )
        return False
    try:
        resource = Resource.create({"service.name": os.environ.get("OTEL_SERVICE_NAME", "pqkms")})
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)
        # Don't trace the unauthenticated probe/metrics endpoints — noise + cardinality.
        FastAPIInstrumentor.instrument_app(app, excluded_urls="/livez,/readyz,/health,/metrics")
        log.info("OpenTelemetry tracing enabled (service.name=%s)", resource.attributes.get("service.name"))
        return True
    except Exception:
        log.exception("failed to initialize OpenTelemetry tracing; continuing without it")
        return False
