# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Hybrid Key Encapsulation: X25519 (classical) + ML-KEM-768 (post-quantum).

The combined shared secret is derived as:
    KDF(ss_classical || ss_pq, salt, "pqkms/hybrid-kem/v1")

This provides IND-CCA2 security as long as *either* component remains secure,
which protects against both future quantum attacks on X25519 and
unexpected cryptanalytic advances against ML-KEM.

Wire format for an encapsulated message:
    [1 byte: suite id][2 bytes: classical_ct_len][classical_ct][pq_ct]
"""
import os
import struct
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from .kdf import derive_key
from .suites import Suite

try:
    import oqs  # liboqs-python
    _OQS_AVAILABLE = True
except ImportError:
    _OQS_AVAILABLE = False

PQ_KEM_ALG = "ML-KEM-768"
X25519_PUB_LEN = 32
X25519_PRIV_LEN = 32
SHARED_SECRET_LEN = 32


@dataclass
class HybridKEMKeypair:
    suite: Suite
    # Public key = classical_pub || pq_pub
    public_key: bytes
    # Private key = classical_priv || pq_priv
    private_key: bytes
    classical_pub_len: int
    pq_pub_len: int


class HybridKEM:
    """
    Hybrid KEM: X25519 + ML-KEM-768.

    If liboqs is unavailable, degrades to classical-only X25519 and marks
    the output with suite CLASSIC_X25519_AES256GCM so it's never confused
    with PQ-protected material at decryption time.
    """

    @staticmethod
    def is_hybrid_available() -> bool:
        return _OQS_AVAILABLE

    @staticmethod
    def generate() -> HybridKEMKeypair:
        # Classical half
        c_priv = X25519PrivateKey.generate()
        c_priv_bytes = c_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        c_pub_bytes = c_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        if not _OQS_AVAILABLE:
            return HybridKEMKeypair(
                suite=Suite.CLASSIC_X25519_AES256GCM,
                public_key=c_pub_bytes,
                private_key=c_priv_bytes,
                classical_pub_len=len(c_pub_bytes),
                pq_pub_len=0,
            )

        # PQ half
        with oqs.KeyEncapsulation(PQ_KEM_ALG) as kem:
            pq_pub_bytes = kem.generate_keypair()
            pq_priv_bytes = kem.export_secret_key()

        return HybridKEMKeypair(
            suite=Suite.HYBRID_X25519_MLKEM768_AES256GCM,
            public_key=c_pub_bytes + pq_pub_bytes,
            private_key=c_priv_bytes + pq_priv_bytes,
            classical_pub_len=len(c_pub_bytes),
            pq_pub_len=len(pq_pub_bytes),
        )

    @staticmethod
    def encapsulate(
        recipient_public_key: bytes,
        suite: Suite,
        classical_pub_len: int = X25519_PUB_LEN,
    ) -> Tuple[bytes, bytes]:
        """
        Generate a shared secret and encapsulation for the recipient.
        Returns (shared_secret, encapsulation_blob).
        """
        c_pub_bytes = recipient_public_key[:classical_pub_len]
        pq_pub_bytes = recipient_public_key[classical_pub_len:]

        # Classical ECDH with ephemeral sender key
        eph_priv = X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        recipient_pub = X25519PublicKey.from_public_bytes(c_pub_bytes)
        ss_classical = eph_priv.exchange(recipient_pub)

        if suite == Suite.CLASSIC_X25519_AES256GCM or not _OQS_AVAILABLE:
            salt = os.urandom(16)
            shared = derive_key(
                ikm=ss_classical,
                salt=salt,
                info=b"pqkms/classical-kem/v1",
            )
            # blob = [suite][salt_len=16][salt][eph_pub_len][eph_pub]
            blob = (
                struct.pack("!BH", int(Suite.CLASSIC_X25519_AES256GCM), len(salt))
                + salt
                + struct.pack("!H", len(eph_pub_bytes))
                + eph_pub_bytes
            )
            return shared, blob

        # Hybrid path: also do ML-KEM encapsulation
        with oqs.KeyEncapsulation(PQ_KEM_ALG) as kem:
            pq_ct, ss_pq = kem.encap_secret(pq_pub_bytes)

        salt = os.urandom(16)
        shared = derive_key(
            ikm=ss_classical + ss_pq,
            salt=salt,
            info=b"pqkms/hybrid-kem/v1",
        )
        blob = (
            struct.pack("!BH", int(Suite.HYBRID_X25519_MLKEM768_AES256GCM), len(salt))
            + salt
            + struct.pack("!H", len(eph_pub_bytes))
            + eph_pub_bytes
            + struct.pack("!I", len(pq_ct))
            + pq_ct
        )
        return shared, blob

    @staticmethod
    def decapsulate(
        recipient_private_key: bytes,
        encapsulation: bytes,
        classical_priv_len: int = X25519_PRIV_LEN,
    ) -> bytes:
        """Recover the shared secret from an encapsulation blob."""
        if len(encapsulation) < 3:
            raise ValueError("encapsulation too short")
        suite_id, salt_len = struct.unpack("!BH", encapsulation[:3])
        suite = Suite(suite_id)
        idx = 3
        salt = encapsulation[idx : idx + salt_len]
        idx += salt_len
        (eph_pub_len,) = struct.unpack("!H", encapsulation[idx : idx + 2])
        idx += 2
        eph_pub_bytes = encapsulation[idx : idx + eph_pub_len]
        idx += eph_pub_len

        c_priv_bytes = recipient_private_key[:classical_priv_len]
        c_priv = X25519PrivateKey.from_private_bytes(c_priv_bytes)
        eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
        ss_classical = c_priv.exchange(eph_pub)

        if suite == Suite.CLASSIC_X25519_AES256GCM:
            return derive_key(
                ikm=ss_classical,
                salt=salt,
                info=b"pqkms/classical-kem/v1",
            )

        if not _OQS_AVAILABLE:
            raise RuntimeError(
                "encapsulation uses hybrid PQ suite but liboqs not available"
            )

        (pq_ct_len,) = struct.unpack("!I", encapsulation[idx : idx + 4])
        idx += 4
        pq_ct = encapsulation[idx : idx + pq_ct_len]

        pq_priv_bytes = recipient_private_key[classical_priv_len:]
        with oqs.KeyEncapsulation(PQ_KEM_ALG, secret_key=pq_priv_bytes) as kem:
            ss_pq = kem.decap_secret(pq_ct)

        return derive_key(
            ikm=ss_classical + ss_pq,
            salt=salt,
            info=b"pqkms/hybrid-kem/v1",
        )
