# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Tests for the Phase 2 hardening: pluggable Root-KEK custody (with legacy-format
fallback), the AES-GCM nonce budget, and API-token TTL/expiry.
"""
import os
from datetime import datetime, timezone, timedelta

import pytest

from app.storage.db import Database
from app.storage.keystore import KeyStore
from app.api.auth import TokenAuth, SCOPES_READ
from app.crypto.aead import AEAD
from app.crypto.kdf import derive_from_passphrase
from app.custody import CustodyEnvelope, PassphraseCustodian
from app.policy import NonceBudgetPolicy, NonceBudgetExceeded


# ---------------------------------------------------------------- custody ----

def test_passphrase_custodian_roundtrip():
    cust = PassphraseCustodian("a-strong-operator-passphrase")
    root = AEAD.generate_key()
    env = cust.initialize(root)
    assert env.backend_id == "passphrase"
    # Round-trip through the on-disk serialization too.
    env2 = CustodyEnvelope.from_bytes(env.to_bytes())
    assert cust.unwrap(env2) == root


def test_passphrase_custodian_wrong_passphrase_rejected():
    env = PassphraseCustodian("right-passphrase-here").initialize(AEAD.generate_key())
    with pytest.raises(ValueError):
        PassphraseCustodian("wrong-passphrase-here").unwrap(CustodyEnvelope.from_bytes(env.to_bytes()))


def test_custody_backend_mismatch_refused():
    cust = PassphraseCustodian("operator-passphrase-1234")
    env = cust.initialize(AEAD.generate_key())
    env.backend_id = "awskms"  # pretend it was sealed by a different backend
    with pytest.raises(RuntimeError):
        cust.unwrap(env)


def test_keystore_uses_custody_envelope(tmp_path):
    db = Database(str(tmp_path / "new.db"))
    ks = KeyStore(db, PassphraseCustodian("init-passphrase-123456"))
    ks.initialize()
    row = db.conn().execute(
        "SELECT v FROM kms_meta WHERE k=?", (KeyStore.META_CUSTODY,)
    ).fetchone()
    assert row is not None, "fresh KMS must persist a custody envelope row"

    # A fresh handle with the same passphrase unlocks to the same Root KEK.
    ks2 = KeyStore(db, PassphraseCustodian("init-passphrase-123456"))
    ks2.unlock()
    assert ks2._root_kek == ks._root_kek


# --------------------------------------------------- legacy-format unlock ----

def _make_legacy_db(tmp_path, passphrase):
    """Reproduce a pre-custodian database: salt + wrapped-root + check rows,
    exactly as the old KeyStore.initialize() wrote them."""
    db = Database(str(tmp_path / "legacy.db"))
    salt = os.urandom(32)
    wrapping_key = derive_from_passphrase(passphrase, salt)  # default Argon2 params
    root_kek = AEAD.generate_key()
    wrapped = AEAD.encrypt(wrapping_key, root_kek, aad=b"pqkms/root-kek/v1")
    check = AEAD.encrypt(wrapping_key, b"pqkms-check", aad=b"pqkms/root-kek-check/v1")
    c = db.conn()
    c.execute("INSERT INTO kms_meta(k,v) VALUES(?,?)", ("root_kek_salt", salt))
    c.execute("INSERT INTO kms_meta(k,v) VALUES(?,?)", ("root_kek_wrapped", wrapped))
    c.execute("INSERT INTO kms_meta(k,v) VALUES(?,?)", ("root_kek_check", check))
    return db, root_kek


def test_legacy_db_unlocks_and_is_usable(tmp_path):
    db, root_kek = _make_legacy_db(tmp_path, "legacy-passphrase-1234")
    ks = KeyStore(db, PassphraseCustodian("legacy-passphrase-1234"))
    assert ks.is_initialized()
    ks.unlock()
    assert ks._root_kek == root_kek
    # And the store is fully functional after a legacy unlock.
    k = ks.create_key("legacy-key", "aead")
    r = ks.encrypt(k.id, b"hello from a legacy db")
    assert ks.decrypt(k.id, r["ciphertext"]) == b"hello from a legacy db"


def test_legacy_db_wrong_passphrase_rejected(tmp_path):
    db, _ = _make_legacy_db(tmp_path, "legacy-passphrase-1234")
    ks = KeyStore(db, PassphraseCustodian("the-wrong-passphrase"))
    with pytest.raises(ValueError):
        ks.unlock()


# ----------------------------------------------------------- nonce budget ----

def test_nonce_budget_hard_limit_fails_closed(tmp_path):
    db = Database(str(tmp_path / "nb.db"))
    ks = KeyStore(
        db,
        PassphraseCustodian("nonce-budget-passphrase"),
        nonce_policy=NonceBudgetPolicy(soft_limit=2, hard_limit=3),
    )
    ks.initialize()
    k = ks.create_key("nb", "aead")
    for i in range(3):  # exactly hard_limit encryptions allowed
        ks.encrypt(k.id, f"msg{i}".encode())
    with pytest.raises(NonceBudgetExceeded):
        ks.encrypt(k.id, b"one too many")


def test_nonce_budget_resets_on_rotation(tmp_path):
    db = Database(str(tmp_path / "nb2.db"))
    ks = KeyStore(
        db,
        PassphraseCustodian("nonce-budget-passphrase"),
        nonce_policy=NonceBudgetPolicy(soft_limit=1, hard_limit=2),
    )
    ks.initialize()
    k = ks.create_key("nb", "aead")
    ks.encrypt(k.id, b"a")
    ks.encrypt(k.id, b"b")
    with pytest.raises(NonceBudgetExceeded):
        ks.encrypt(k.id, b"c")
    # Rotation creates a fresh version with a zero counter.
    ks.rotate(k.id)
    out = ks.encrypt(k.id, b"d")
    assert out["version"] == 2


# -------------------------------------------------------------- token TTL ----

def test_token_without_ttl_does_not_expire(tmp_path):
    auth = TokenAuth(Database(str(tmp_path / "t.db")))
    _tid, tok = auth.create_token("perm", {SCOPES_READ})
    assert auth.verify(tok) == {SCOPES_READ}


def test_token_with_future_ttl_verifies(tmp_path):
    auth = TokenAuth(Database(str(tmp_path / "t.db")))
    _tid, tok = auth.create_token("temp", {SCOPES_READ}, ttl_seconds=3600)
    assert auth.verify(tok) == {SCOPES_READ}


def test_token_expired_rejected(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    auth = TokenAuth(db)
    tid, tok = auth.create_token("temp", {SCOPES_READ}, ttl_seconds=3600)
    # Force-expire without sleeping.
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    db.conn().execute("UPDATE api_tokens SET expires_at=? WHERE id=?", (past, tid))
    assert auth.verify(tok) is None


def test_token_negative_ttl_rejected(tmp_path):
    auth = TokenAuth(Database(str(tmp_path / "t.db")))
    with pytest.raises(ValueError):
        auth.create_token("bad", {SCOPES_READ}, ttl_seconds=-5)
