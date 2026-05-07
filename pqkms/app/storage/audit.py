# Copyright (c) 2026 DarkShadowSec LLC. All Rights Reserved.
# Proprietary and confidential. See LICENSE for terms.
"""
Append-only audit log with hash chain + hybrid signatures.

Each entry's hash includes the previous entry's hash, so any tampering with
historical entries invalidates the chain from that point forward. Each entry
is also hybrid-signed, so an attacker needs both the classical and PQ signing
keys to forge entries (and even then the hash chain exposes history edits).
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

from .db import Database
from ..crypto.signatures import HybridSigner
from ..crypto.suites import Suite


class AuditLog:
    def __init__(self, db: Database, signing_keypair: tuple[bytes, bytes, Suite]):
        """signing_keypair: (private, public, suite) for log signing."""
        self.db = db
        self._priv, self._pub, self._suite = signing_keypair

    def append(self, actor: str, action: str, target: Optional[str] = None, detail: Optional[dict] = None) -> int:
        c = self.db.conn()
        prev = c.execute("SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = bytes(prev["entry_hash"]) if prev else b"\x00" * 32

        ts = datetime.now(timezone.utc).isoformat()
        detail_json = json.dumps(detail or {}, sort_keys=True)
        payload = f"{ts}|{actor}|{action}|{target or ''}|{detail_json}".encode()
        entry_hash = hashlib.sha384(prev_hash + payload).digest()
        signature = HybridSigner.sign(self._priv, entry_hash, self._suite)

        cur = c.execute(
            "INSERT INTO audit_log(ts,actor,action,target,detail,prev_hash,entry_hash,signature) VALUES(?,?,?,?,?,?,?,?)",
            (ts, actor, action, target, detail_json, prev_hash, entry_hash, signature),
        )
        return cur.lastrowid

    def verify_chain(self) -> tuple[bool, Optional[int]]:
        """Walk the chain, return (ok, first_bad_seq_or_None)."""
        c = self.db.conn()
        rows = c.execute("SELECT * FROM audit_log ORDER BY seq ASC").fetchall()
        prev_hash = b"\x00" * 32
        for r in rows:
            if bytes(r["prev_hash"]) != prev_hash:
                return False, r["seq"]
            payload = f"{r['ts']}|{r['actor']}|{r['action']}|{r['target'] or ''}|{r['detail']}".encode()
            expected = hashlib.sha384(prev_hash + payload).digest()
            if expected != bytes(r["entry_hash"]):
                return False, r["seq"]
            if not HybridSigner.verify(self._pub, expected, bytes(r["signature"])):
                return False, r["seq"]
            prev_hash = expected
        return True, None

    def list(self, limit: int = 200) -> list[dict]:
        c = self.db.conn()
        rows = c.execute(
            "SELECT seq, ts, actor, action, target, detail FROM audit_log ORDER BY seq DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
