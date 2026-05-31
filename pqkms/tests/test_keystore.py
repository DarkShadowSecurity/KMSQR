# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""KeyStore integration tests."""
import os
import tempfile
import base64
import pytest
from sqlalchemy import text

from app.storage.repository import make_repository
from app.storage.keystore import KeyStore
from app.storage.audit import AuditLog
from app.crypto.signatures import HybridSigner


def _repo(tmp_path, name="test.db"):
    return make_repository(f"sqlite:///{(tmp_path / name).as_posix()}")


@pytest.fixture
def ks(tmp_path):
    store = KeyStore(_repo(tmp_path))
    store.initialize("test-passphrase")
    return store


def test_passphrase_unlock(tmp_path):
    store = KeyStore(_repo(tmp_path))
    store.initialize("hunter2")
    assert store.is_unlocked()

    # Simulate a restart: a fresh handle on the same database file.
    store2 = KeyStore(_repo(tmp_path))
    assert not store2.is_unlocked()
    store2.unlock("hunter2")
    assert store2.is_unlocked()


def test_wrong_passphrase_rejected(tmp_path):
    store = KeyStore(_repo(tmp_path))
    store.initialize("correct")

    store2 = KeyStore(_repo(tmp_path))
    with pytest.raises(ValueError):
        store2.unlock("wrong")


def test_aead_key_encrypt_decrypt(ks):
    k = ks.create_key("mykey", "aead")
    result = ks.encrypt(k.id, b"sensitive data", aad=b"context")
    pt = ks.decrypt(k.id, result["ciphertext"], aad=b"context")
    assert pt == b"sensitive data"


def test_aead_rotation_preserves_old_ciphertexts(ks):
    k = ks.create_key("rotate-me", "aead")
    # Encrypt under v1
    r1 = ks.encrypt(k.id, b"data from v1")
    # Rotate
    ks.rotate(k.id)
    # Encrypt under v2
    r2 = ks.encrypt(k.id, b"data from v2")
    # Both should decrypt successfully
    assert ks.decrypt(k.id, r1["ciphertext"]) == b"data from v1"
    assert ks.decrypt(k.id, r2["ciphertext"]) == b"data from v2"
    # New version should actually be v2
    assert r2["version"] == 2


def test_sig_key_sign_verify(ks):
    k = ks.create_key("signer", "sig")
    r = ks.sign(k.id, b"important message")
    assert ks.verify(k.id, b"important message", r["signature"])
    assert not ks.verify(k.id, b"tampered message", r["signature"])


def test_kem_key_wrap_unwrap(ks):
    k = ks.create_key("wrapper", "kem")
    data_key = os.urandom(32)
    r = ks.wrap_data_key(k.id, data_key)
    recovered = ks.unwrap_data_key(k.id, r["encapsulation"], r["wrapped_key"])
    assert recovered == data_key


def test_audit_chain_tamper_detection(tmp_path):
    repo = _repo(tmp_path)
    store = KeyStore(repo)
    store.initialize("pass")

    # Create an audit log signing keypair
    kp = HybridSigner.generate()
    audit = AuditLog(repo, (kp.private_key, kp.public_key, kp.suite))

    audit.append("alice", "test.action", target="t1", detail={"x": 1})
    audit.append("bob", "test.action", target="t2", detail={"x": 2})
    audit.append("carol", "test.action", target="t3")

    ok, bad = audit.verify_chain()
    assert ok and bad is None

    # Tamper with the middle entry directly in storage.
    with repo.engine.begin() as c:
        c.execute(text("UPDATE audit_log SET detail = :d WHERE seq = 2"), {"d": '{"x": 999}'})
    ok, bad = audit.verify_chain()
    assert not ok
    assert bad == 2
