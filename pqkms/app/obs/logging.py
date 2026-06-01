# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Structured logging + request-id propagation.

A contextvar carries the per-request id so every log line emitted while handling
a request — including the generic 500 handler — is correlatable with the
`request_id` returned to the caller and the `X-Request-ID` response header.

PQKMS_LOG_FORMAT=json emits one JSON object per line (for log shippers);
anything else keeps the human-readable text format. PQKMS_LOG_LEVEL sets the
level (default INFO).
"""
from __future__ import annotations

import json
import logging
import os
import sys
from contextvars import ContextVar

request_id_var: ContextVar[str] = ContextVar("pqkms_request_id", default="-")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        obj = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": request_id_var.get(),
        }
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        # Allow ad-hoc structured fields via logging `extra={"fields": {...}}`.
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            obj.update(extra)
        return json.dumps(obj, default=str)


class TextFormatter(logging.Formatter):
    def __init__(self):
        super().__init__("%(asctime)s %(levelname)s %(name)s [%(request_id)s] :: %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        record.request_id = request_id_var.get()
        return super().format(record)


def configure_logging() -> None:
    fmt = os.environ.get("PQKMS_LOG_FORMAT", "text").strip().lower()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(os.environ.get("PQKMS_LOG_LEVEL", "INFO").upper())
