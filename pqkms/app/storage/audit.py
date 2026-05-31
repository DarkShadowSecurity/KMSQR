# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
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

from .repository import Repository
from ..crypto.signatures import HybridSigner
from ..crypto.suites import Suite


class AuditLog:
    def __init__(self, repo: Repository, signing_keypair: tuple[bytes, bytes, Suite]):
        """signing_keypair: (private, public, suite) for log signing."""
        self.repo = repo
        self._priv, self._pub, self._suite = signing_keypair

    def append(self, actor: str, action: str, target: Optional[str] = None, detail: Optional[dict] = None) -> int:
        ts = datetime.now(timezone.utc).isoformat()
        detail_json = json.dumps(detail or {}, sort_keys=True)

        def build(prev_hash: bytes) -> dict:
            payload = f"{ts}|{actor}|{action}|{target or ''}|{detail_json}".encode()
            entry_hash = hashlib.sha384(prev_hash + payload).digest()
            signature = HybridSigner.sign(self._priv, entry_hash, self._suite)
            return {
                "ts": ts, "actor": actor, "action": action, "target": target,
                "detail": detail_json, "prev_hash": prev_hash,
                "entry_hash": entry_hash, "signature": signature,
            }

        # The read-of-prev-hash + insert happen atomically inside the repository.
        return self.repo.append_audit(build)

    def verify_chain(self) -> tuple[bool, Optional[int]]:
        """Walk the chain, return (ok, first_bad_seq_or_None)."""
        prev_hash = b"\x00" * 32
        for r in self.repo.iter_audit_asc():
            if r["prev_hash"] != prev_hash:
                return False, r["seq"]
            payload = f"{r['ts']}|{r['actor']}|{r['action']}|{r['target'] or ''}|{r['detail']}".encode()
            expected = hashlib.sha384(prev_hash + payload).digest()
            if expected != r["entry_hash"]:
                return False, r["seq"]
            if not HybridSigner.verify(self._pub, expected, r["signature"]):
                return False, r["seq"]
            prev_hash = expected
        return True, None

    def list(self, limit: int = 200) -> list[dict]:
        return self.repo.list_audit_desc(limit)
