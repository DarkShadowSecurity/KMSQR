# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Prometheus metrics + a request-observability middleware.

The middleware assigns/propagates a request id, times each request, records
metrics keyed by the matched ROUTE TEMPLATE (not the raw path — so per-key URLs
like /keys/{key_id}/encrypt collapse to one low-cardinality series), and emits a
structured access log line.

Scrape /metrics from the internal network only (the reverse proxy must not
expose it publicly).
"""
from __future__ import annotations

import logging
import time
import uuid

from fastapi import Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware

from .logging import request_id_var

log = logging.getLogger("pqkms.access")

REQUESTS = Counter(
    "pqkms_http_requests_total", "Total HTTP requests", ["method", "route", "status"]
)
LATENCY = Histogram(
    "pqkms_http_request_duration_seconds", "HTTP request latency (s)", ["method", "route"]
)
UNLOCKED = Gauge("pqkms_unlocked", "1 if the KMS keystore is unlocked, else 0")


def set_unlocked(is_unlocked: bool) -> None:
    UNLOCKED.set(1 if is_unlocked else 0)


def _route_template(request: Request) -> str:
    # Starlette sets scope["route"] once routing matches; its .path is the
    # template (e.g. "/api/v1/keys/{key_id}/encrypt"). Falls back for 404s.
    route = request.scope.get("route")
    return getattr(route, "path", None) or "unmatched"


def metrics_response() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


class RequestObservabilityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
        token = request_id_var.set(rid)
        start = time.perf_counter()
        method = request.method
        try:
            response = await call_next(request)
            status = response.status_code
        except Exception:
            # Should be rare (FastAPI converts handled exceptions to responses),
            # but record and re-raise so nothing is lost.
            route = _route_template(request)
            REQUESTS.labels(method, route, "500").inc()
            LATENCY.labels(method, route).observe(time.perf_counter() - start)
            request_id_var.reset(token)
            raise

        duration = time.perf_counter() - start
        route = _route_template(request)
        REQUESTS.labels(method, route, str(status)).inc()
        LATENCY.labels(method, route).observe(duration)
        response.headers["X-Request-ID"] = rid
        log.info(
            "%s %s -> %d (%.1fms)", method, route, status, duration * 1000,
            extra={"fields": {"method": method, "route": route, "status": status,
                              "duration_ms": round(duration * 1000, 1)}},
        )
        request_id_var.reset(token)
        return response
