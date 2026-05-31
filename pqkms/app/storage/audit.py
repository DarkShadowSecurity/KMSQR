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
import logging
import struct
from datetime import datetime, timezone
from typing import Optional

from .repository import Repository
from .audit_sink import AuditSink, NullAuditSink
from ..crypto.signatures import HybridSigner
from ..crypto.suites import Suite, SUITE_NAMES

log = logging.getLogger("pqkms.audit")

_AUDIT_SIGNING_META_KEY = "audit_signing_keypair_v1"
_AUDIT_SIGNING_AAD = b"pqkms/audit-signing/v1"


class AuditLog:
    def __init__(
        self,
        repo: Repository,
        signing_keypair: tuple[bytes, bytes, Suite],
        sink: Optional[AuditSink] = None,
    ):
        """signing_keypair: (private, public, suite) for log signing.
        sink: optional external append-only destination (WORM file, etc.)."""
        self.repo = repo
        self._priv, self._pub, self._suite = signing_keypair
        self._sink = sink or NullAuditSink()

    def append(self, actor: str, action: str, target: Optional[str] = None, detail: Optional[dict] = None) -> int:
        ts = datetime.now(timezone.utc).isoformat()
        detail_json = json.dumps(detail or {}, sort_keys=True)
        built: dict = {}

        def build(prev_hash: bytes) -> dict:
            payload = f"{ts}|{actor}|{action}|{target or ''}|{detail_json}".encode()
            entry_hash = hashlib.sha384(prev_hash + payload).digest()
            signature = HybridSigner.sign(self._priv, entry_hash, self._suite)
            row = {
                "ts": ts, "actor": actor, "action": action, "target": target,
                "detail": detail_json, "prev_hash": prev_hash,
                "entry_hash": entry_hash, "signature": signature,
            }
            built.clear()
            built.update(row)
            return row

        # The read-of-prev-hash + insert happen atomically inside the repository
        # (serialized across replicas). `built` holds the row that actually
        # committed (after any retry), which we then mirror to the external sink.
        seq = self.repo.append_audit(build)
        try:
            self._sink.emit({**built, "seq": seq})
        except Exception:
            # The DB write already committed; a sink failure must not undo it.
            log.exception("audit sink emit failed for seq=%s", seq)
        return seq

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


def load_or_create_audit_signing_key(ks) -> tuple[bytes, bytes, Suite]:
    """
    Load the audit-log signing keypair, generating it on first run. The keypair
    is stored as a meta row encrypted under the Root KEK (so the audit log stays
    tamper-evident even if the DB is copied off-box). Creation is race-safe
    across replicas: the writer that loses the if_absent insert simply loads the
    keypair that won. `ks` must be an unlocked KeyStore.

    Stored format: [2B suite][4B priv_len][priv][pub].
    """
    def _parse(raw: bytes) -> tuple[bytes, bytes, Suite]:
        suite_id, priv_len = struct.unpack("!HI", raw[:6])
        priv = raw[6:6 + priv_len]
        pub = raw[6 + priv_len:]
        return priv, pub, Suite(suite_id)

    existing = ks.repo.get_meta(_AUDIT_SIGNING_META_KEY)
    if existing is not None:
        return _parse(ks._unwrap(existing, aad=_AUDIT_SIGNING_AAD))

    kp = HybridSigner.generate()
    packed = struct.pack("!HI", int(kp.suite), len(kp.private_key)) + kp.private_key + kp.public_key
    wrapped = ks._wrap(packed, aad=_AUDIT_SIGNING_AAD)
    if ks.repo.put_meta(_AUDIT_SIGNING_META_KEY, wrapped, if_absent=True):
        log.info("generated new audit-log signing keypair (%s)", SUITE_NAMES[kp.suite])
        return kp.private_key, kp.public_key, kp.suite

    # Another replica generated and stored one first — use theirs.
    return _parse(ks._unwrap(ks.repo.get_meta(_AUDIT_SIGNING_META_KEY), aad=_AUDIT_SIGNING_AAD))
