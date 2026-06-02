# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Audit sinks: stream each committed audit entry to an external, append-only
destination so the log is tamper-EVIDENT in the DB *and* independently
verifiable off-box.

FileAuditSink writes one canonical JSON line per entry and fsyncs it. Because
audit appends are globally serialized by the repository, file lines are globally
ordered and form the same hash chain as the DB — an attacker who tampers with
the database (but cannot also rewrite the append-only file) is caught by
cross-checking the two. Point the file at a mount with append-only/WORM
semantics (e.g. `chattr +a`, or object storage with retention) for hard
guarantees; the AuditSink interface lets syslog/HTTP/Kafka shippers slot in
later without touching AuditLog.
"""
from __future__ import annotations

import abc
import base64
import json
import os
from typing import Optional


def entry_to_json(entry: dict) -> dict:
    """Canonical, JSON-serializable view of an audit row (binary fields base64)."""
    return {
        "seq": entry.get("seq"),
        "ts": entry["ts"],
        "actor": entry["actor"],
        "action": entry["action"],
        "target": entry.get("target"),
        "detail": entry.get("detail"),
        "prev_hash_b64": base64.b64encode(entry["prev_hash"]).decode(),
        "entry_hash_b64": base64.b64encode(entry["entry_hash"]).decode(),
        "signature_b64": base64.b64encode(entry["signature"]).decode(),
    }


_CEF_ESCAPE = str.maketrans({"\\": "\\\\", "=": "\\=", "\n": " ", "\r": " "})


def _cef_field(v) -> str:
    return str(v if v is not None else "").translate(_CEF_ESCAPE)


def entry_to_cef(entry: dict) -> str:
    """ArcSight CEF line for SIEM ingestion (Splunk/QRadar/Sentinel parse CEF).
    Header: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension."""
    ext = {
        "rt": _cef_field(entry.get("ts")),
        "suser": _cef_field(entry.get("actor")),
        "act": _cef_field(entry.get("action")),
        "cs1Label": "target", "cs1": _cef_field(entry.get("target")),
        "cs2Label": "detail", "cs2": _cef_field(entry.get("detail")),
        "cn1Label": "seq", "cn1": _cef_field(entry.get("seq")),
    }
    extension = " ".join(f"{k}={v}" for k, v in ext.items())
    action = _cef_field(entry.get("action"))
    return f"CEF:0|DarkShadowSec|PQ-KMS|1.0|{action}|{action}|3|{extension}"


class AuditSink(abc.ABC):
    @abc.abstractmethod
    def emit(self, entry: dict) -> None:
        """Persist one committed audit entry. Must not raise on transient issues
        in a way that would roll back the (already committed) DB write."""


class NullAuditSink(AuditSink):
    def emit(self, entry: dict) -> None:  # noqa: D401
        return None


class FileAuditSink(AuditSink):
    def __init__(self, path: str, fmt: str = "json"):
        self.path = path
        self.fmt = fmt
        # Ensure the parent dir exists; fail loudly at construction, not per-write.
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)

    def _format(self, entry: dict) -> str:
        if self.fmt == "cef":
            return entry_to_cef(entry)
        return json.dumps(entry_to_json(entry), sort_keys=True)

    def emit(self, entry: dict) -> None:
        line = self._format(entry)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())


def make_audit_sink(path: Optional[str], fmt: str = "json") -> AuditSink:
    if not path:
        return NullAuditSink()
    if fmt not in ("json", "cef"):
        raise RuntimeError(f"PQKMS_AUDIT_LOG_FORMAT must be 'json' or 'cef', got {fmt!r}")
    return FileAuditSink(path, fmt=fmt)
