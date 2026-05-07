# Copyright (c) 2026 DarkShadowSec LLC. All Rights Reserved.
# Proprietary and confidential. See LICENSE for terms.
"""
Hybrid signatures: Ed25519 (classical) + ML-DSA-65 (post-quantum).

Signature format: [2 bytes: suite][4 bytes: classical_sig_len][classical_sig][pq_sig]
Verification requires BOTH signatures to validate.
"""
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from .suites import Suite

try:
    import oqs
    _OQS_AVAILABLE = True
except ImportError:
    _OQS_AVAILABLE = False

PQ_SIG_ALG = "ML-DSA-65"
ED25519_PUB_LEN = 32
ED25519_PRIV_LEN = 32


@dataclass
class HybridSigKeypair:
    suite: Suite
    public_key: bytes
    private_key: bytes
    classical_pub_len: int


class HybridSigner:

    @staticmethod
    def is_hybrid_available() -> bool:
        return _OQS_AVAILABLE

    @staticmethod
    def generate() -> HybridSigKeypair:
        c_priv = Ed25519PrivateKey.generate()
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
            return HybridSigKeypair(
                suite=Suite.CLASSIC_ED25519,
                public_key=c_pub_bytes,
                private_key=c_priv_bytes,
                classical_pub_len=len(c_pub_bytes),
            )

        with oqs.Signature(PQ_SIG_ALG) as sig:
            pq_pub_bytes = sig.generate_keypair()
            pq_priv_bytes = sig.export_secret_key()

        return HybridSigKeypair(
            suite=Suite.HYBRID_ED25519_MLDSA65,
            public_key=c_pub_bytes + pq_pub_bytes,
            private_key=c_priv_bytes + pq_priv_bytes,
            classical_pub_len=len(c_pub_bytes),
        )

    @staticmethod
    def sign(
        private_key: bytes,
        message: bytes,
        suite: Suite,
        classical_priv_len: int = ED25519_PRIV_LEN,
    ) -> bytes:
        c_priv_bytes = private_key[:classical_priv_len]
        c_priv = Ed25519PrivateKey.from_private_bytes(c_priv_bytes)
        c_sig = c_priv.sign(message)

        if suite == Suite.CLASSIC_ED25519 or not _OQS_AVAILABLE:
            return (
                struct.pack("!HI", int(Suite.CLASSIC_ED25519), len(c_sig))
                + c_sig
            )

        pq_priv_bytes = private_key[classical_priv_len:]
        with oqs.Signature(PQ_SIG_ALG, secret_key=pq_priv_bytes) as signer:
            pq_sig = signer.sign(message)

        return (
            struct.pack("!HI", int(Suite.HYBRID_ED25519_MLDSA65), len(c_sig))
            + c_sig
            + pq_sig
        )

    @staticmethod
    def verify(
        public_key: bytes,
        message: bytes,
        signature: bytes,
        classical_pub_len: int = ED25519_PUB_LEN,
    ) -> bool:
        if len(signature) < 6:
            return False
        suite_id, c_sig_len = struct.unpack("!HI", signature[:6])
        try:
            suite = Suite(suite_id)
        except ValueError:
            return False
        c_sig = signature[6 : 6 + c_sig_len]
        pq_sig = signature[6 + c_sig_len :]

        c_pub_bytes = public_key[:classical_pub_len]
        try:
            Ed25519PublicKey.from_public_bytes(c_pub_bytes).verify(c_sig, message)
        except InvalidSignature:
            return False

        if suite == Suite.CLASSIC_ED25519:
            return True

        if not _OQS_AVAILABLE:
            return False

        pq_pub_bytes = public_key[classical_pub_len:]
        try:
            with oqs.Signature(PQ_SIG_ALG) as verifier:
                return verifier.verify(message, pq_sig, pq_pub_bytes)
        except Exception:
            return False
