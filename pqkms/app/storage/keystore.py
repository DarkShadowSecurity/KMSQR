# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
KeyStore: the heart of the KMS.

Key hierarchy:
    Passphrase (or HSM-backed secret)
      └─ Argon2id ─> Root-KEK-wrapping key
            └─ decrypts ─> Root KEK (AES-256)
                  └─ AEAD-wraps ─> every managed key's secret material

Managed keys are versioned. Rotation creates a new version; old versions remain
available for decryption but not for encryption. This gives clean key lifecycle
management without breaking stored ciphertexts.
"""
import os
import json
import uuid
import base64
import struct
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional

from ..crypto.aead import AEAD
from ..crypto.kem import HybridKEM
from ..crypto.signatures import HybridSigner
from ..crypto.kdf import DEFAULT_ARGON2_PARAMS
from ..crypto.suites import Suite, SUITE_NAMES
from ..custody import CustodyEnvelope, PassphraseCustodian, RootKeyCustodian
from ..policy import NonceBudgetPolicy
from .db import Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ManagedKey:
    id: str
    name: str
    key_type: str
    current_version: int
    created_at: str
    description: Optional[str]
    suite: int
    public_material: Optional[str]  # base64, or None for symmetric


class KeyStore:
    """
    Manages the Root KEK and all subordinate keys.

    The Root KEK is generated on first bootstrap, AEAD-encrypted under a
    key derived from the operator passphrase (Argon2id), and stored in
    the kms_meta table. On startup, the operator supplies the passphrase
    to unlock it. The Root KEK never leaves memory in plaintext after that.
    """

    # Legacy meta keys (pre-custodian format). Retained read-only so databases
    # created before pluggable custody unlock transparently.
    META_SALT = "root_kek_salt"
    META_WRAPPED_ROOT = "root_kek_wrapped"
    META_ROOT_CHECK = "root_kek_check"
    # Current format: a single self-describing custody envelope.
    META_CUSTODY = "root_kek_custody_v1"

    def __init__(
        self,
        db: Database,
        custodian: Optional[RootKeyCustodian] = None,
        nonce_policy: Optional[NonceBudgetPolicy] = None,
    ):
        self.db = db
        self._custodian = custodian
        self._nonce_policy = nonce_policy or NonceBudgetPolicy()
        self._root_kek: Optional[bytes] = None

    def _resolve_custodian(self, passphrase: Optional[str]) -> RootKeyCustodian:
        """Use the configured custodian if present; otherwise, for backward
        compatibility, build a passphrase custodian from a passphrase argument."""
        if self._custodian is not None:
            return self._custodian
        if passphrase is not None:
            return PassphraseCustodian(passphrase)
        raise RuntimeError("no custodian configured and no passphrase provided")

    # ---- bootstrap / unlock ----

    def is_initialized(self) -> bool:
        cur = self.db.conn().execute(
            "SELECT 1 FROM kms_meta WHERE k IN (?, ?) LIMIT 1",
            (self.META_CUSTODY, self.META_WRAPPED_ROOT),
        )
        return cur.fetchone() is not None

    def initialize(self, passphrase: Optional[str] = None) -> None:
        if self.is_initialized():
            raise RuntimeError("KMS already initialized")
        custodian = self._resolve_custodian(passphrase)
        custodian.healthcheck()
        root_kek = AEAD.generate_key()
        envelope = custodian.initialize(root_kek)
        with self.db.conn() as c:
            c.execute(
                "INSERT INTO kms_meta(k,v) VALUES(?,?)",
                (self.META_CUSTODY, envelope.to_bytes()),
            )
        self._root_kek = root_kek

    def unlock(self, passphrase: Optional[str] = None) -> None:
        if not self.is_initialized():
            raise RuntimeError("KMS not initialized")
        custodian = self._resolve_custodian(passphrase)
        envelope = self._load_envelope(custodian)
        self._root_kek = custodian.unwrap(envelope)

    def _load_envelope(self, custodian: RootKeyCustodian) -> CustodyEnvelope:
        c = self.db.conn()
        row = c.execute("SELECT v FROM kms_meta WHERE k=?", (self.META_CUSTODY,)).fetchone()
        if row is not None:
            return CustodyEnvelope.from_bytes(bytes(row["v"]))

        # Legacy fallback: synthesize an envelope from the pre-custodian rows so a
        # passphrase custodian unwraps an old database with no migration step. The
        # legacy AAD and Argon2 params match PassphraseCustodian's defaults exactly.
        salt = c.execute("SELECT v FROM kms_meta WHERE k=?", (self.META_SALT,)).fetchone()
        wrapped = c.execute("SELECT v FROM kms_meta WHERE k=?", (self.META_WRAPPED_ROOT,)).fetchone()
        if salt is None or wrapped is None:
            raise RuntimeError("KMS not initialized")
        if custodian.backend_id != "passphrase":
            raise RuntimeError(
                "this database uses legacy passphrase custody; cannot unlock with "
                f"backend {custodian.backend_id!r}"
            )
        return CustodyEnvelope(
            backend_id="passphrase",
            wrapped_root_kek=bytes(wrapped["v"]),
            metadata={
                "salt_b64": base64.b64encode(bytes(salt["v"])).decode(),
                "argon2": DEFAULT_ARGON2_PARAMS,
            },
        )

    def is_unlocked(self) -> bool:
        return self._root_kek is not None

    def _require_unlocked(self):
        if self._root_kek is None:
            raise RuntimeError("KMS is locked — provide passphrase to unlock")

    # ---- envelope wrap/unwrap under root KEK ----

    def _wrap(self, plaintext: bytes, aad: bytes) -> bytes:
        self._require_unlocked()
        return AEAD.encrypt(self._root_kek, plaintext, aad=aad)

    def _unwrap(self, ciphertext: bytes, aad: bytes) -> bytes:
        self._require_unlocked()
        return AEAD.decrypt(self._root_kek, ciphertext, aad=aad)

    # ---- managed keys ----

    def create_key(
        self,
        name: str,
        key_type: str,
        description: Optional[str] = None,
    ) -> ManagedKey:
        """
        Create a new managed key. Types:
            'aead'  — AES-256-GCM symmetric key
            'kem'   — hybrid X25519+ML-KEM-768 keypair for wrapping
            'sig'   — hybrid Ed25519+ML-DSA-65 signing keypair
        """
        self._require_unlocked()
        key_id = str(uuid.uuid4())
        suite, secret, public = self._generate_material(key_type)
        aad = f"pqkms/key/{key_id}/v1".encode()
        wrapped = self._wrap(secret, aad)

        with self.db.conn() as c:
            c.execute(
                "INSERT INTO managed_keys(id,name,key_type,current_version,created_at,description) VALUES(?,?,?,?,?,?)",
                (key_id, name, key_type, 1, _now(), description),
            )
            c.execute(
                "INSERT INTO key_versions(key_id,version,suite,wrapped_secret,public_material,created_at,state) VALUES(?,?,?,?,?,?,?)",
                (key_id, 1, int(suite), wrapped, public, _now(), "active"),
            )

        return ManagedKey(
            id=key_id, name=name, key_type=key_type, current_version=1,
            created_at=_now(), description=description, suite=int(suite),
            public_material=base64.b64encode(public).decode() if public else None,
        )

    def _generate_material(self, key_type: str):
        if key_type == "aead":
            return Suite.AES256_GCM, AEAD.generate_key(), None
        if key_type == "kem":
            kp = HybridKEM.generate()
            return kp.suite, kp.private_key, kp.public_key
        if key_type == "sig":
            kp = HybridSigner.generate()
            return kp.suite, kp.private_key, kp.public_key
        raise ValueError(f"unknown key_type: {key_type}")

    def list_keys(self) -> list[ManagedKey]:
        c = self.db.conn()
        rows = c.execute("""
            SELECT mk.*, kv.suite, kv.public_material
            FROM managed_keys mk
            JOIN key_versions kv
              ON kv.key_id = mk.id AND kv.version = mk.current_version
            ORDER BY mk.created_at DESC
        """).fetchall()
        return [
            ManagedKey(
                id=r["id"], name=r["name"], key_type=r["key_type"],
                current_version=r["current_version"], created_at=r["created_at"],
                description=r["description"], suite=r["suite"],
                public_material=base64.b64encode(bytes(r["public_material"])).decode() if r["public_material"] else None,
            ) for r in rows
        ]

    def get_key(self, key_id: str) -> Optional[ManagedKey]:
        c = self.db.conn()
        r = c.execute("""
            SELECT mk.*, kv.suite, kv.public_material
            FROM managed_keys mk
            JOIN key_versions kv ON kv.key_id = mk.id AND kv.version = mk.current_version
            WHERE mk.id = ?
        """, (key_id,)).fetchone()
        if not r:
            return None
        return ManagedKey(
            id=r["id"], name=r["name"], key_type=r["key_type"],
            current_version=r["current_version"], created_at=r["created_at"],
            description=r["description"], suite=r["suite"],
            public_material=base64.b64encode(bytes(r["public_material"])).decode() if r["public_material"] else None,
        )

    def rotate(self, key_id: str) -> ManagedKey:
        """Generate a new version. Old versions stay available for decrypt/verify."""
        self._require_unlocked()
        mk = self.get_key(key_id)
        if not mk:
            raise KeyError(key_id)
        new_version = mk.current_version + 1
        suite, secret, public = self._generate_material(mk.key_type)
        aad = f"pqkms/key/{key_id}/v{new_version}".encode()
        wrapped = self._wrap(secret, aad)

        with self.db.conn() as c:
            c.execute(
                "UPDATE key_versions SET state='rotated' WHERE key_id=? AND version=?",
                (key_id, mk.current_version),
            )
            c.execute(
                "INSERT INTO key_versions(key_id,version,suite,wrapped_secret,public_material,created_at,state) VALUES(?,?,?,?,?,?,?)",
                (key_id, new_version, int(suite), wrapped, public, _now(), "active"),
            )
            c.execute(
                "UPDATE managed_keys SET current_version=? WHERE id=?",
                (new_version, key_id),
            )
        return self.get_key(key_id)

    def _load_version(self, key_id: str, version: int):
        """Returns (suite, secret_bytes, public_bytes_or_none). Unwraps secret."""
        c = self.db.conn()
        r = c.execute(
            "SELECT suite, wrapped_secret, public_material FROM key_versions WHERE key_id=? AND version=?",
            (key_id, version),
        ).fetchone()
        if not r:
            raise KeyError(f"{key_id}@v{version}")
        aad = f"pqkms/key/{key_id}/v{version}".encode()
        secret = self._unwrap(bytes(r["wrapped_secret"]), aad)
        pub = bytes(r["public_material"]) if r["public_material"] else None
        return Suite(r["suite"]), secret, pub

    # ---- high-level crypto operations ----

    def encrypt(self, key_id: str, plaintext: bytes, aad: bytes = b"") -> dict:
        mk = self.get_key(key_id)
        if not mk or mk.key_type != "aead":
            raise ValueError("key not found or not an AEAD key")
        suite, secret, _ = self._load_version(key_id, mk.current_version)
        # Reserve one slot in this key-version's AES-GCM nonce budget *before*
        # encrypting. Fails closed (NonceBudgetExceeded) at the hard cap so we
        # never approach the random-96-bit-nonce birthday bound.
        self._nonce_policy.reserve(self.db, key_id, mk.current_version)
        blob = AEAD.encrypt(secret, plaintext, aad)
        # Tag with key_id@version and suite so decrypt can route correctly
        header = struct.pack("!BI", int(suite), mk.current_version)
        return {
            "key_id": key_id,
            "version": mk.current_version,
            "suite": SUITE_NAMES[suite],
            "ciphertext": base64.b64encode(header + blob).decode(),
        }

    def decrypt(self, key_id: str, ciphertext_b64: str, aad: bytes = b"") -> bytes:
        raw = base64.b64decode(ciphertext_b64)
        if len(raw) < 5:
            raise ValueError("ciphertext too short")
        _suite_id, version = struct.unpack("!BI", raw[:5])
        blob = raw[5:]
        _, secret, _ = self._load_version(key_id, version)
        return AEAD.decrypt(secret, blob, aad)

    def sign(self, key_id: str, message: bytes) -> dict:
        mk = self.get_key(key_id)
        if not mk or mk.key_type != "sig":
            raise ValueError("key not found or not a signing key")
        suite, secret, public = self._load_version(key_id, mk.current_version)
        sig = HybridSigner.sign(secret, message, suite)
        return {
            "key_id": key_id,
            "version": mk.current_version,
            "suite": SUITE_NAMES[suite],
            "signature": base64.b64encode(sig).decode(),
            "public_key": base64.b64encode(public).decode(),
        }

    def verify(self, key_id: str, message: bytes, signature_b64: str, version: Optional[int] = None) -> bool:
        mk = self.get_key(key_id)
        if not mk or mk.key_type != "sig":
            raise ValueError("key not found or not a signing key")
        v = version or mk.current_version
        _, _, public = self._load_version(key_id, v)
        return HybridSigner.verify(public, message, base64.b64decode(signature_b64))

    def wrap_data_key(self, key_id: str, data_key: bytes) -> dict:
        """Hybrid-KEM-wrap a symmetric data key for storage or transport."""
        mk = self.get_key(key_id)
        if not mk or mk.key_type != "kem":
            raise ValueError("key not found or not a KEM key")
        suite, _, public = self._load_version(key_id, mk.current_version)
        shared, encap = HybridKEM.encapsulate(public, suite)
        wrapped = AEAD.encrypt(shared, data_key, aad=b"pqkms/wrap/v1")
        return {
            "key_id": key_id,
            "version": mk.current_version,
            "suite": SUITE_NAMES[suite],
            "encapsulation": base64.b64encode(encap).decode(),
            "wrapped_key": base64.b64encode(wrapped).decode(),
        }

    def unwrap_data_key(self, key_id: str, encapsulation_b64: str, wrapped_b64: str, version: Optional[int] = None) -> bytes:
        mk = self.get_key(key_id)
        if not mk or mk.key_type != "kem":
            raise ValueError("key not found or not a KEM key")
        v = version or mk.current_version
        _, secret, _ = self._load_version(key_id, v)
        shared = HybridKEM.decapsulate(secret, base64.b64decode(encapsulation_b64))
        return AEAD.decrypt(shared, base64.b64decode(wrapped_b64), aad=b"pqkms/wrap/v1")
