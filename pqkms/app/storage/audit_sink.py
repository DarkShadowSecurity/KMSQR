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


class AuditSink(abc.ABC):
    @abc.abstractmethod
    def emit(self, entry: dict) -> None:
        """Persist one committed audit entry. Must not raise on transient issues
        in a way that would roll back the (already committed) DB write."""


class NullAuditSink(AuditSink):
    def emit(self, entry: dict) -> None:  # noqa: D401
        return None


class FileAuditSink(AuditSink):
    def __init__(self, path: str):
        self.path = path
        # Ensure the parent dir exists; fail loudly at construction, not per-write.
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)

    def emit(self, entry: dict) -> None:
        line = json.dumps(entry_to_json(entry), sort_keys=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())


def make_audit_sink(path: Optional[str]) -> AuditSink:
    return FileAuditSink(path) if path else NullAuditSink()
