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
from .repository import Repository


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
    namespace_id: Optional[str] = None
    state: str = "enabled"          # 'enabled' | 'disabled' | 'pending_deletion'
    deletion_at: Optional[str] = None
    origin: str = "generated"        # 'generated' | 'imported'


# Lifecycle states.
KEY_ENABLED = "enabled"
KEY_DISABLED = "disabled"
KEY_PENDING_DELETION = "pending_deletion"


class KeyStateError(Exception):
    """Raised when an operation is attempted on a key whose lifecycle state
    forbids it (disabled or pending deletion)."""


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
        repo: Repository,
        custodian: Optional[RootKeyCustodian] = None,
        nonce_policy: Optional[NonceBudgetPolicy] = None,
    ):
        self.repo = repo
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
        return self.repo.meta_exists_any([self.META_CUSTODY, self.META_WRAPPED_ROOT])

    def initialize(self, passphrase: Optional[str] = None) -> None:
        if self.is_initialized():
            raise RuntimeError("KMS already initialized")
        custodian = self._resolve_custodian(passphrase)
        custodian.healthcheck()
        root_kek = AEAD.generate_key()
        envelope = custodian.initialize(root_kek)
        # if_absent makes bootstrap race-safe across replicas: only the first
        # writer's Root KEK becomes authoritative. A loser discards its freshly
        # generated key and unlocks from the envelope that actually landed.
        if self.repo.put_meta(self.META_CUSTODY, envelope.to_bytes(), if_absent=True):
            self._root_kek = root_kek
        else:
            self._root_kek = custodian.unwrap(self._load_envelope(custodian))

    def unlock(self, passphrase: Optional[str] = None) -> None:
        if not self.is_initialized():
            raise RuntimeError("KMS not initialized")
        custodian = self._resolve_custodian(passphrase)
        envelope = self._load_envelope(custodian)
        self._root_kek = custodian.unwrap(envelope)

    def _load_envelope(self, custodian: RootKeyCustodian) -> CustodyEnvelope:
        raw = self.repo.get_meta(self.META_CUSTODY)
        if raw is not None:
            return CustodyEnvelope.from_bytes(raw)

        # Legacy fallback: synthesize an envelope from the pre-custodian rows so a
        # passphrase custodian unwraps an old database with no migration step. The
        # legacy AAD and Argon2 params match PassphraseCustodian's defaults exactly.
        salt = self.repo.get_meta(self.META_SALT)
        wrapped = self.repo.get_meta(self.META_WRAPPED_ROOT)
        if salt is None or wrapped is None:
            raise RuntimeError("KMS not initialized")
        if custodian.backend_id != "passphrase":
            raise RuntimeError(
                "this database uses legacy passphrase custody; cannot unlock with "
                f"backend {custodian.backend_id!r}"
            )
        return CustodyEnvelope(
            backend_id="passphrase",
            wrapped_root_kek=wrapped,
            metadata={
                "salt_b64": base64.b64encode(salt).decode(),
                "argon2": DEFAULT_ARGON2_PARAMS,
            },
        )

    def rewrap_root_kek(self, new_custodian: RootKeyCustodian) -> None:
        """
        Re-seal the EXISTING Root KEK under a new custodian (e.g. after an
        operator passphrase change). Subordinate key material is untouched — only
        the custody envelope is replaced — so this is cheap regardless of how many
        managed keys exist. Requires the store to be unlocked. Writing the new
        custody envelope also transparently migrates a legacy-format database to
        the current envelope format.
        """
        self._require_unlocked()
        new_custodian.healthcheck()
        new_envelope = new_custodian.initialize(self._root_kek)
        self.repo.set_meta(self.META_CUSTODY, new_envelope.to_bytes())

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
        namespace_id: Optional[str] = None,
    ) -> ManagedKey:
        """
        Create a new managed key. Types:
            'aead'  — AES-256-GCM symmetric key
            'kem'   — hybrid X25519+ML-KEM-768 keypair for wrapping
            'sig'   — hybrid Ed25519+ML-DSA-65 signing keypair

        namespace_id places the key in a key-ring (tenant). Callers resolve it
        from a namespace name; the API layer defaults it to the 'default'
        namespace.
        """
        self._require_unlocked()
        key_id = str(uuid.uuid4())
        suite, secret, public = self._generate_material(key_type)
        aad = f"pqkms/key/{key_id}/v1".encode()
        wrapped = self._wrap(secret, aad)
        created_at = _now()

        self.repo.create_key_with_version(
            mk={
                "id": key_id, "name": name, "key_type": key_type,
                "current_version": 1, "created_at": created_at, "description": description,
                "namespace_id": namespace_id, "state": KEY_ENABLED,
                "deletion_at": None, "origin": "generated",
            },
            kv={
                "key_id": key_id, "version": 1, "suite": int(suite),
                "wrapped_secret": wrapped, "public_material": public,
                "created_at": created_at, "state": "active",
            },
        )

        return ManagedKey(
            id=key_id, name=name, key_type=key_type, current_version=1,
            created_at=created_at, description=description, suite=int(suite),
            public_material=base64.b64encode(public).decode() if public else None,
            namespace_id=namespace_id, state=KEY_ENABLED, origin="generated",
        )

    def import_key(
        self,
        name: str,
        key_material: bytes,
        description: Optional[str] = None,
        namespace_id: Optional[str] = None,
    ) -> ManagedKey:
        """BYOK: create a managed AEAD key from externally supplied material
        (e.g. exported from another KMS or an HSM). The material must be a 32-byte
        AES-256 key. It is wrapped under the Root KEK exactly like generated keys;
        only its `origin` differs ('imported'), which is surfaced for audit."""
        self._require_unlocked()
        if len(key_material) != 32:
            raise ValueError("imported AEAD key material must be exactly 32 bytes")
        key_id = str(uuid.uuid4())
        aad = f"pqkms/key/{key_id}/v1".encode()
        wrapped = self._wrap(key_material, aad)
        created_at = _now()
        self.repo.create_key_with_version(
            mk={
                "id": key_id, "name": name, "key_type": "aead",
                "current_version": 1, "created_at": created_at, "description": description,
                "namespace_id": namespace_id, "state": KEY_ENABLED,
                "deletion_at": None, "origin": "imported",
            },
            kv={
                "key_id": key_id, "version": 1, "suite": int(Suite.AES256_GCM),
                "wrapped_secret": wrapped, "public_material": None,
                "created_at": created_at, "state": "active",
            },
        )
        return ManagedKey(
            id=key_id, name=name, key_type="aead", current_version=1,
            created_at=created_at, description=description, suite=int(Suite.AES256_GCM),
            public_material=None, namespace_id=namespace_id, state=KEY_ENABLED, origin="imported",
        )

    # ---- lifecycle ----

    def _require_enabled(self, key_id: str) -> "ManagedKey":
        """Fetch a key and require it to be enabled. Raises KeyError if missing,
        KeyStateError if disabled / pending deletion. Used to gate crypto ops so a
        disabled or to-be-destroyed key cannot be used."""
        mk = self.get_key(key_id)
        if not mk:
            raise KeyError(key_id)
        if mk.state != KEY_ENABLED:
            raise KeyStateError(f"key is {mk.state}")
        return mk

    def disable_key(self, key_id: str) -> "ManagedKey":
        if not self.get_key(key_id):
            raise KeyError(key_id)
        self.repo.set_key_state(key_id, KEY_DISABLED, deletion_at=None)
        return self.get_key(key_id)

    def enable_key(self, key_id: str) -> "ManagedKey":
        mk = self.get_key(key_id)
        if not mk:
            raise KeyError(key_id)
        if mk.state == KEY_PENDING_DELETION:
            # Re-enabling a pending key is done via cancel_deletion (-> disabled).
            raise KeyStateError("key is pending deletion; cancel deletion first")
        self.repo.set_key_state(key_id, KEY_ENABLED, deletion_at=None)
        return self.get_key(key_id)

    def schedule_deletion(self, key_id: str, window_days: int) -> "ManagedKey":
        if not self.get_key(key_id):
            raise KeyError(key_id)
        if window_days < 0:
            raise ValueError("window_days must be >= 0")
        from datetime import timedelta
        deletion_at = (datetime.now(timezone.utc) + timedelta(days=window_days)).isoformat()
        self.repo.set_key_state(key_id, KEY_PENDING_DELETION, deletion_at=deletion_at)
        return self.get_key(key_id)

    def cancel_deletion(self, key_id: str) -> "ManagedKey":
        mk = self.get_key(key_id)
        if not mk:
            raise KeyError(key_id)
        if mk.state != KEY_PENDING_DELETION:
            raise KeyStateError("key is not pending deletion")
        # Cancellation returns the key to disabled (operator must explicitly
        # re-enable), matching common cloud-KMS semantics.
        self.repo.set_key_state(key_id, KEY_DISABLED, deletion_at=None)
        return self.get_key(key_id)

    def destroy_key(self, key_id: str, *, force: bool = False) -> None:
        """Permanently and irreversibly destroy a key. Only permitted once the key
        is pending deletion and its window has elapsed, unless force=True (admin
        override). Destroying a key makes every ciphertext under it undecryptable."""
        mk = self.get_key(key_id)
        if not mk:
            raise KeyError(key_id)
        if not force:
            if mk.state != KEY_PENDING_DELETION:
                raise KeyStateError("key must be pending deletion before destruction")
            if mk.deletion_at is None or datetime.now(timezone.utc) < datetime.fromisoformat(mk.deletion_at):
                raise KeyStateError("deletion window has not elapsed")
        self.repo.destroy_key(key_id)

    def export_public_key(self, key_id: str) -> dict:
        """Return the public half of an asymmetric (sig/kem) key. AEAD keys have no
        public material and raise ValueError."""
        mk = self.get_key(key_id)
        if not mk:
            raise KeyError(key_id)
        if mk.public_material is None:
            raise ValueError("key has no public material (symmetric key)")
        return {
            "key_id": key_id,
            "version": mk.current_version,
            "key_type": mk.key_type,
            "suite": SUITE_NAMES[Suite(mk.suite)],
            "public_key_b64": mk.public_material,
        }

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

    @staticmethod
    def _row_to_managed_key(r: dict) -> ManagedKey:
        return ManagedKey(
            id=r["id"], name=r["name"], key_type=r["key_type"],
            current_version=r["current_version"], created_at=r["created_at"],
            description=r["description"], suite=r["suite"],
            public_material=base64.b64encode(r["public_material"]).decode() if r["public_material"] else None,
            namespace_id=r.get("namespace_id"),
            state=r.get("state") or KEY_ENABLED,
            deletion_at=r.get("deletion_at"),
            origin=r.get("origin") or "generated",
        )

    def list_keys(self, *, limit: int = 200, offset: int = 0) -> list[ManagedKey]:
        return [self._row_to_managed_key(r) for r in self.repo.list_keys_current(limit=limit, offset=offset)]

    def get_key(self, key_id: str) -> Optional[ManagedKey]:
        r = self.repo.get_key_current(key_id)
        return self._row_to_managed_key(r) if r else None

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

        self.repo.rotate_key(
            key_id=key_id,
            old_version=mk.current_version,
            kv={
                "key_id": key_id, "version": new_version, "suite": int(suite),
                "wrapped_secret": wrapped, "public_material": public,
                "created_at": _now(), "state": "active",
            },
            new_version=new_version,
        )
        return self.get_key(key_id)

    def _load_version(self, key_id: str, version: int):
        """Returns (suite, secret_bytes, public_bytes_or_none). Unwraps secret."""
        r = self.repo.get_version(key_id, version)
        if r is None:
            raise KeyError(f"{key_id}@v{version}")
        aad = f"pqkms/key/{key_id}/v{version}".encode()
        secret = self._unwrap(r["wrapped_secret"], aad)
        return Suite(r["suite"]), secret, r["public_material"]

    # ---- high-level crypto operations ----

    def encrypt(self, key_id: str, plaintext: bytes, aad: bytes = b"") -> dict:
        mk = self._require_enabled(key_id)
        if mk.key_type != "aead":
            raise ValueError("key not found or not an AEAD key")
        suite, secret, _ = self._load_version(key_id, mk.current_version)
        # Reserve one slot in this key-version's AES-GCM nonce budget *before*
        # encrypting. Fails closed (NonceBudgetExceeded) at the hard cap so we
        # never approach the random-96-bit-nonce birthday bound.
        self._nonce_policy.reserve(self.repo, key_id, mk.current_version)
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
        self._require_enabled(key_id)
        raw = base64.b64decode(ciphertext_b64)
        if len(raw) < 5:
            raise ValueError("ciphertext too short")
        _suite_id, version = struct.unpack("!BI", raw[:5])
        blob = raw[5:]
        _, secret, _ = self._load_version(key_id, version)
        return AEAD.decrypt(secret, blob, aad)

    def sign(self, key_id: str, message: bytes) -> dict:
        mk = self._require_enabled(key_id)
        if mk.key_type != "sig":
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
        suite, _, public = self._load_version(key_id, v)
        # Pass the key's stored suite so a downgraded (classical-tagged) signature
        # cannot bypass the post-quantum half of a hybrid key.
        return HybridSigner.verify(public, message, base64.b64decode(signature_b64), expected_suite=suite)

    def wrap_data_key(self, key_id: str, data_key: bytes) -> dict:
        """Hybrid-KEM-wrap a symmetric data key for storage or transport."""
        mk = self._require_enabled(key_id)
        if mk.key_type != "kem":
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
        mk = self._require_enabled(key_id)
        if mk.key_type != "kem":
            raise ValueError("key not found or not a KEM key")
        v = version or mk.current_version
        _, secret, _ = self._load_version(key_id, v)
        shared = HybridKEM.decapsulate(secret, base64.b64decode(encapsulation_b64))
        return AEAD.decrypt(shared, base64.b64decode(wrapped_b64), aad=b"pqkms/wrap/v1")
