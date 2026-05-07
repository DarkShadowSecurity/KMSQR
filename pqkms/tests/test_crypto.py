# Copyright (c) 2026 DarkShadowSec LLC. All Rights Reserved.
# Proprietary and confidential. See LICENSE for terms.
"""Unit tests for the crypto primitives."""
import os
import pytest

from app.crypto.aead import AEAD
from app.crypto.kem import HybridKEM
from app.crypto.signatures import HybridSigner
from app.crypto.kdf import derive_key, derive_from_passphrase
from app.crypto.suites import Suite


def test_aead_roundtrip():
    key = AEAD.generate_key()
    pt = b"this is secret payload data"
    ct = AEAD.encrypt(key, pt, aad=b"ctx")
    assert AEAD.decrypt(key, ct, aad=b"ctx") == pt


def test_aead_wrong_aad_fails():
    key = AEAD.generate_key()
    ct = AEAD.encrypt(key, b"pt", aad=b"a")
    with pytest.raises(Exception):
        AEAD.decrypt(key, ct, aad=b"b")


def test_aead_wrong_key_fails():
    ct = AEAD.encrypt(AEAD.generate_key(), b"pt")
    with pytest.raises(Exception):
        AEAD.decrypt(AEAD.generate_key(), ct)


def test_hybrid_kem_roundtrip():
    kp = HybridKEM.generate()
    shared, encap = HybridKEM.encapsulate(kp.public_key, kp.suite, kp.classical_pub_len)
    recovered = HybridKEM.decapsulate(kp.private_key, encap)
    assert shared == recovered
    assert len(shared) == 32


def test_hybrid_kem_tampered_encap_fails():
    kp = HybridKEM.generate()
    shared, encap = HybridKEM.encapsulate(kp.public_key, kp.suite, kp.classical_pub_len)
    # Flip bits in the middle of the encapsulation — must either raise or yield wrong secret
    mid = len(encap) // 2
    tampered = encap[:mid] + bytes([encap[mid] ^ 0xFF]) + encap[mid+1:]
    try:
        out = HybridKEM.decapsulate(kp.private_key, tampered)
        assert out != shared, "tampered encapsulation should not yield original secret"
    except Exception:
        pass  # raising is also an acceptable outcome


def test_hybrid_sig_roundtrip():
    kp = HybridSigner.generate()
    msg = b"authentic message"
    sig = HybridSigner.sign(kp.private_key, msg, kp.suite)
    assert HybridSigner.verify(kp.public_key, msg, sig)


def test_hybrid_sig_tampered_message_fails():
    kp = HybridSigner.generate()
    msg = b"authentic message"
    sig = HybridSigner.sign(kp.private_key, msg, kp.suite)
    assert not HybridSigner.verify(kp.public_key, b"different message", sig)


def test_hybrid_sig_tampered_signature_fails():
    kp = HybridSigner.generate()
    msg = b"authentic message"
    sig = HybridSigner.sign(kp.private_key, msg, kp.suite)
    bad = bytearray(sig)
    bad[20] ^= 0xFF  # flip a bit in the classical signature portion
    assert not HybridSigner.verify(kp.public_key, msg, bytes(bad))


def test_hybrid_sig_wrong_key_fails():
    kp1 = HybridSigner.generate()
    kp2 = HybridSigner.generate()
    sig = HybridSigner.sign(kp1.private_key, b"msg", kp1.suite)
    assert not HybridSigner.verify(kp2.public_key, b"msg", sig)


def test_hkdf_determinism():
    ikm = b"input-keying-material"
    salt = os.urandom(16)
    k1 = derive_key(ikm, salt, b"info")
    k2 = derive_key(ikm, salt, b"info")
    assert k1 == k2
    k3 = derive_key(ikm, salt, b"different-info")
    assert k1 != k3


def test_argon2_determinism():
    salt = os.urandom(32)
    k1 = derive_from_passphrase("correct horse battery staple", salt)
    k2 = derive_from_passphrase("correct horse battery staple", salt)
    assert k1 == k2
    k3 = derive_from_passphrase("different passphrase", salt)
    assert k1 != k3
