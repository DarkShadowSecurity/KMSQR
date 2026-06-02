# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Resource authorization: which keys a principal may operate on.

Two axes work together:
  * Scopes (on the credential) are the *capability ceiling* — what kinds of
    operations the token may ever perform. Enforced by require_scope in auth.py,
    in every mode.
  * Grants (principal x resource -> operations) are the *resource restriction* —
    which specific keys (or whole namespaces) the principal may touch. Enforced
    here, only in strict mode.

Modes (PQKMS_AUTHZ_MODE):
  * legacy (default): historical behaviour — a scope authorizes the operation on
    *any* key. Grants are ignored. Upgrading deployments see no change.
  * strict: a non-admin principal must additionally hold a grant covering both
    the operation and the target key (directly, or via the key's namespace).

The admin scope is a global superuser: it bypasses grant checks in every mode.
"""
from __future__ import annotations

import logging
import os

from fastapi import HTTPException

from .auth import Caller

log = logging.getLogger("pqkms.authz")

# Grantable operations. Note wrap maps to ENCRYPT and unwrap to DECRYPT at the
# route layer, so the KEM operations reuse the same two grant operations.
OP_ENCRYPT = "encrypt"
OP_DECRYPT = "decrypt"
OP_SIGN = "sign"
OP_VERIFY = "verify"
OP_READ = "read"
OP_MANAGE = "manage"  # create / rotate / lifecycle

ALL_OPS = {OP_ENCRYPT, OP_DECRYPT, OP_SIGN, OP_VERIFY, OP_READ, OP_MANAGE}

RESOURCE_KEY = "key"
RESOURCE_NAMESPACE = "namespace"
RESOURCE_TYPES = {RESOURCE_KEY, RESOURCE_NAMESPACE}

MODE_LEGACY = "legacy"
MODE_STRICT = "strict"
_MODES = {MODE_LEGACY, MODE_STRICT}


def resolve_mode(value: str | None = None) -> str:
    """Resolve the authorization mode from the argument or PQKMS_AUTHZ_MODE.
    Defaults to legacy. An unknown value fails fast — better than silently
    running in the wrong posture for a KMS."""
    mode = (value if value is not None else os.environ.get("PQKMS_AUTHZ_MODE", MODE_LEGACY)).strip().lower()
    if mode not in _MODES:
        raise RuntimeError(f"PQKMS_AUTHZ_MODE must be one of {sorted(_MODES)}, got {mode!r}")
    return mode


def parse_operations(raw) -> set[str]:
    """Validate and normalize an operations list/csv to a set, rejecting unknowns."""
    if isinstance(raw, str):
        items = [o.strip() for o in raw.split(",") if o.strip()]
    else:
        items = [str(o).strip() for o in raw]
    ops = set(items)
    if not ops:
        raise ValueError("at least one operation is required")
    bad = ops - ALL_OPS
    if bad:
        raise ValueError(f"unknown operations: {sorted(bad)}")
    return ops


class Authorizer:
    def __init__(self, repo, mode: str = MODE_LEGACY):
        self.repo = repo
        self.mode = mode

    @property
    def strict(self) -> bool:
        return self.mode == MODE_STRICT

    # ---- grant lookup ----

    def _principal_ops(self, principal_id: str | None) -> dict[tuple[str, str], set[str]]:
        """Map (resource_type, resource_id) -> set(operations) for a principal."""
        if not principal_id:
            return {}
        out: dict[tuple[str, str], set[str]] = {}
        for g in self.repo.get_grants_for_principal(principal_id):
            ops = {o for o in g["operations"].split(",") if o}
            out[(g["resource_type"], g["resource_id"])] = ops
        return out

    def _allows(self, principal_id: str | None, op: str, key_id: str | None, namespace_id: str | None) -> bool:
        grants = self._principal_ops(principal_id)
        if key_id is not None and op in grants.get((RESOURCE_KEY, key_id), set()):
            return True
        if namespace_id is not None and op in grants.get((RESOURCE_NAMESPACE, namespace_id), set()):
            return True
        return False

    # ---- enforcement (raise on deny, return on allow) ----

    def authorize_key_op(self, caller: Caller, op: str, key_id: str) -> None:
        """Authorize an operation on a key (strict mode only for non-admins).
        Raises 403 if the caller lacks a grant covering the operation on the key
        or its namespace. A missing key resolves to namespace None and thus 403,
        which also avoids leaking key existence to unauthorized callers."""
        if caller.is_admin or not self.strict:
            return
        namespace_id = self.repo.get_key_namespace(key_id)
        if not self._allows(caller.principal_id, op, key_id, namespace_id):
            log.info("authz deny: principal=%s op=%s key=%s", caller.principal_id, op, key_id)
            raise HTTPException(403, f"no grant for {op} on this key")

    def authorize_namespace_op(self, caller: Caller, op: str, namespace_id: str) -> None:
        """Authorize an operation scoped to a namespace (e.g. creating a key in it)."""
        if caller.is_admin or not self.strict:
            return
        if not self._allows(caller.principal_id, op, None, namespace_id):
            log.info("authz deny: principal=%s op=%s namespace=%s", caller.principal_id, op, namespace_id)
            raise HTTPException(403, f"no grant for {op} in this namespace")

    def filter_visible_keys(self, caller: Caller, keys: list) -> list:
        """Restrict a key listing to those the caller may read. Admin / legacy
        mode see everything; otherwise a key is visible if the principal has a
        read grant on it or on its namespace."""
        if caller.is_admin or not self.strict:
            return keys
        grants = self._principal_ops(caller.principal_id)
        readable_keys = {rid for (rtype, rid), ops in grants.items() if rtype == RESOURCE_KEY and OP_READ in ops}
        readable_ns = {rid for (rtype, rid), ops in grants.items() if rtype == RESOURCE_NAMESPACE and OP_READ in ops}
        return [k for k in keys if k.id in readable_keys or (k.namespace_id in readable_ns)]
