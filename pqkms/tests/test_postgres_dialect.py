# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Cross-dialect repository tests.

Runs the full storage surface (custody envelope, managed keys + versions, audit
hash-chain, tokens, nonce budget) against whatever backend PQKMS_TEST_DB_URL
points at. Skipped unless that env var is set, so the default test run stays
SQLite-only; CI sets it to a PostgreSQL container to prove dialect parity
(RETURNING, BYTEA, IDENTITY autoincrement, LIKE prefix lookups).
"""
import os
import uuid

import pytest

from app.storage.repository import make_repository
from app.storage.keystore import KeyStore
from app.storage.audit import AuditLog
from app.api.auth import TokenAuth, SCOPES_READ
from app.crypto.signatures import HybridSigner
from app.custody import PassphraseCustodian
from app.policy import NonceBudgetPolicy, NonceBudgetExceeded

PG_URL = os.environ.get("PQKMS_TEST_DB_URL")
pytestmark = pytest.mark.skipif(not PG_URL, reason="PQKMS_TEST_DB_URL not set")


@pytest.fixture
def repo():
    # Unique passphrase/key names per run so repeated runs against a persistent
    # database don't collide on the UNIQUE(name) constraint.
    return make_repository(PG_URL)


def test_keystore_full_lifecycle(repo):
    ks = KeyStore(repo, PassphraseCustodian("pg-operator-passphrase"))
    if not ks.is_initialized():
        ks.initialize()
    else:
        ks.unlock()

    tag = uuid.uuid4().hex[:8]
    aead = ks.create_key(f"aead-{tag}", "aead")
    sig = ks.create_key(f"sig-{tag}", "sig")
    kem = ks.create_key(f"kem-{tag}", "kem")

    # AEAD round-trip across a rotation.
    enc = ks.encrypt(aead.id, b"postgres secret", aad=b"ctx")
    assert ks.decrypt(aead.id, enc["ciphertext"], aad=b"ctx") == b"postgres secret"
    ks.rotate(aead.id)
    assert ks.decrypt(aead.id, enc["ciphertext"], aad=b"ctx") == b"postgres secret"

    # Sign / verify and KEM wrap / unwrap.
    s = ks.sign(sig.id, b"msg")
    assert ks.verify(sig.id, b"msg", s["signature"])
    dk = os.urandom(32)
    w = ks.wrap_data_key(kem.id, dk)
    assert ks.unwrap_data_key(kem.id, w["encapsulation"], w["wrapped_key"]) == dk


def test_audit_chain_on_backend(repo):
    ks = KeyStore(repo, PassphraseCustodian("pg-operator-passphrase"))
    if not ks.is_initialized():
        ks.initialize()
    else:
        ks.unlock()
    kp = HybridSigner.generate()
    audit = AuditLog(repo, (kp.private_key, kp.public_key, kp.suite))
    for i in range(5):
        audit.append("tester", "pg.action", target=f"t{i}", detail={"i": i})
    ok, bad = audit.verify_chain()
    assert ok and bad is None


def test_tokens_and_nonce_budget_on_backend(repo):
    auth = TokenAuth(repo)
    _tid, tok = auth.create_token(f"reader-{uuid.uuid4().hex[:8]}", {SCOPES_READ}, ttl_seconds=3600)
    assert auth.verify(tok) == {SCOPES_READ}

    ks = KeyStore(
        repo,
        PassphraseCustodian("pg-operator-passphrase"),
        nonce_policy=NonceBudgetPolicy(soft_limit=1, hard_limit=2),
    )
    if not ks.is_initialized():
        ks.initialize()
    else:
        ks.unlock()
    k = ks.create_key(f"nb-{uuid.uuid4().hex[:8]}", "aead")
    ks.encrypt(k.id, b"a")
    ks.encrypt(k.id, b"b")
    with pytest.raises(NonceBudgetExceeded):
        ks.encrypt(k.id, b"c")
