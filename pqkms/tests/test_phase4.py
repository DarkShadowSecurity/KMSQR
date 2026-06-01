# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Phase 4: audit HA-correctness (serialized append + UNIQUE(prev_hash) fork guard),
race-safe bootstrap, and the WORM file sink + cross-verification.
"""
import base64
import hashlib
import json

import pytest
from sqlalchemy import text

from app.storage.repository import make_repository
from app.storage.keystore import KeyStore
from app.storage.audit import AuditLog, load_or_create_audit_signing_key
from app.storage.audit_sink import FileAuditSink
from app.custody import PassphraseCustodian
from app.crypto.signatures import HybridSigner


def _repo(tmp_path, name="test.db"):
    return make_repository(f"sqlite:///{(tmp_path / name).as_posix()}")


def _audit(repo, sink=None):
    kp = HybridSigner.generate()
    return AuditLog(repo, (kp.private_key, kp.public_key, kp.suite), sink=sink)


def test_prev_hash_unique_index_blocks_fork(tmp_path):
    repo = _repo(tmp_path)
    audit = _audit(repo)
    audit.append("a", "x")
    # Manually forging a second row with a duplicate prev_hash must be rejected
    # by the UNIQUE(prev_hash) index — the chain cannot fork at the storage layer.
    row = repo.iter_audit_asc()[0]
    with pytest.raises(Exception):
        with repo.engine.begin() as c:
            c.execute(text(
                "INSERT INTO audit_log(ts,actor,action,target,detail,prev_hash,entry_hash,signature) "
                "VALUES('t','a','x',NULL,'{}',:p,:e,:s)"
            ), {"p": row["prev_hash"], "e": b"\x01" * 48, "s": b"\x02" * 8})


def test_append_chain_is_valid_and_sequential(tmp_path):
    repo = _repo(tmp_path)
    audit = _audit(repo)
    seqs = [audit.append("svc", "act", target=f"t{i}", detail={"i": i}) for i in range(20)]
    assert seqs == sorted(seqs) and len(set(seqs)) == 20
    ok, bad = audit.verify_chain()
    assert ok and bad is None


def test_file_sink_writes_and_cross_verifies(tmp_path):
    repo = _repo(tmp_path)
    log_file = tmp_path / "audit.jsonl"
    audit = _audit(repo, sink=FileAuditSink(str(log_file)))
    for i in range(5):
        audit.append("svc", "act", target=f"t{i}", detail={"i": i})

    # The file holds one JSON line per entry and forms the same hash chain.
    lines = [json.loads(l) for l in log_file.read_text().splitlines() if l.strip()]
    assert len(lines) == 5
    prev = b"\x00" * 32
    for e in lines:
        assert base64.b64decode(e["prev_hash_b64"]) == prev
        payload = f"{e['ts']}|{e['actor']}|{e['action']}|{e.get('target') or ''}|{e['detail']}".encode()
        expected = hashlib.sha384(prev + payload).digest()
        assert base64.b64decode(e["entry_hash_b64"]) == expected
        prev = expected
    # File head must equal the DB head.
    db_head = repo.iter_audit_asc()[-1]["entry_hash"]
    assert base64.b64decode(lines[-1]["entry_hash_b64"]) == db_head


def test_initialize_loser_falls_back_to_unlock(tmp_path, monkeypatch):
    # Simulate the concurrent-bootstrap loser: a second replica that passed the
    # is_initialized() fast-path before the first committed. Its if_absent insert
    # loses, so instead of clobbering the Root KEK it unlocks the stored envelope
    # — both must end up with the same key.
    repo = _repo(tmp_path)
    a = KeyStore(repo, PassphraseCustodian("race-passphrase-1234"))
    a.initialize()

    b = KeyStore(_repo(tmp_path), PassphraseCustodian("race-passphrase-1234"))
    monkeypatch.setattr(b, "is_initialized", lambda: False)  # force into the body
    b.initialize()
    assert b._root_kek == a._root_kek


def test_audit_signing_key_is_stable_across_loads(tmp_path):
    repo = _repo(tmp_path)
    ks = KeyStore(repo, PassphraseCustodian("audit-key-passphrase-1"))
    ks.initialize()
    p1, pub1, s1 = load_or_create_audit_signing_key(ks)
    p2, pub2, s2 = load_or_create_audit_signing_key(ks)
    assert (p1, pub1, s1) == (p2, pub2, s2)
