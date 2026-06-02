# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Token authentication. Tokens are stored as SHA-384 hashes; the raw token is
only returned once at creation time. Scopes control what each token can do.
"""
import hashlib
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import HTTPException, Header

from ..storage.repository import Repository


SCOPES_ADMIN = "admin"
SCOPES_ENCRYPT = "encrypt"
SCOPES_DECRYPT = "decrypt"
SCOPES_SIGN = "sign"
SCOPES_VERIFY = "verify"
SCOPES_READ = "read"

ALL_SCOPES = {SCOPES_ADMIN, SCOPES_ENCRYPT, SCOPES_DECRYPT, SCOPES_SIGN, SCOPES_VERIFY, SCOPES_READ}

PRINCIPAL_TYPES = {"service", "human"}


def _hash_token(token: str) -> bytes:
    return hashlib.sha384(token.encode()).digest()


@dataclass(frozen=True)
class Caller:
    """The authenticated identity behind a request: the principal (who) plus the
    scopes its credential carries (what it may do). Routes record principal_id as
    the audit actor so every action is attributable to a real identity."""

    principal_id: Optional[str]
    display_name: Optional[str]
    scopes: set[str] = field(default_factory=set)

    @property
    def is_admin(self) -> bool:
        return SCOPES_ADMIN in self.scopes

    @property
    def actor(self) -> str:
        """Stable audit actor string. Prefer the principal id; fall back to the
        scope set only for credentials with no principal (shouldn't occur after
        migration, but keeps auditing robust)."""
        if self.principal_id:
            return f"principal:{self.principal_id}"
        return f"token[{','.join(sorted(self.scopes))}]"


class TokenAuth:
    def __init__(self, repo: Repository):
        self.repo = repo

    def has_any_token(self) -> bool:
        return self.repo.has_any_token()

    # ---- principals ----

    def create_principal(self, display_name: str, ptype: str = "service") -> str:
        if ptype not in PRINCIPAL_TYPES:
            raise ValueError(f"unknown principal type: {ptype!r}")
        pid = str(uuid.uuid4())
        self.repo.insert_principal({
            "id": pid,
            "ptype": ptype,
            "display_name": display_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "disabled": 0,
        })
        return pid

    def list_principals(self) -> list[dict]:
        return self.repo.list_principals()

    def get_principal(self, principal_id: str) -> Optional[dict]:
        return self.repo.get_principal(principal_id)

    def set_principal_disabled(self, principal_id: str, disabled: bool) -> bool:
        return self.repo.set_principal_disabled(principal_id, disabled)

    def delete_principal(self, principal_id: str) -> bool:
        return self.repo.delete_principal(principal_id)

    # ---- tokens ----

    def create_token(
        self,
        name: str,
        scopes: set[str],
        ttl_seconds: Optional[int] = None,
        principal_id: Optional[str] = None,
    ) -> tuple[str, str, str]:
        """Mint a token. If principal_id is given the token authenticates as that
        existing principal; otherwise a new service principal (named after the
        token) is created and the token is bound to it. Returns
        (token_id, raw_token, principal_id)."""
        bad = scopes - ALL_SCOPES
        if bad:
            raise ValueError(f"unknown scopes: {bad}")
        if ttl_seconds is not None and ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

        if principal_id is None:
            principal_id = self.create_principal(name, ptype="service")
        elif self.repo.get_principal(principal_id) is None:
            raise ValueError(f"unknown principal: {principal_id}")

        tid = str(uuid.uuid4())
        raw = secrets.token_urlsafe(32)
        formatted = f"pqkms_{tid[:8]}_{raw}"
        now = datetime.now(timezone.utc)
        expires_at = None
        if ttl_seconds is not None:
            expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
        # Hash the formatted token — that's what verify() will see on the wire.
        self.repo.insert_token({
            "id": tid,
            "token_hash": _hash_token(formatted),
            "name": name,
            "scopes": ",".join(sorted(scopes)),
            "created_at": now.isoformat(),
            "revoked": 0,
            "expires_at": expires_at,
            "principal_id": principal_id,
        })
        return tid, formatted, principal_id

    def revoke(self, token_id: str):
        self.repo.revoke_token(token_id)

    def list_tokens(self) -> list[dict]:
        return self.repo.list_tokens()

    def authenticate(self, raw_token: str) -> Optional[Caller]:
        """Resolve a raw bearer token to a Caller, or None if it is invalid,
        revoked, expired, or its principal is disabled."""
        # Tokens look like pqkms_<tid_prefix>_<secret>, where tid_prefix is the
        # first 8 chars of the token's UUID id. We narrow to candidates by that
        # indexed id prefix (typically exactly one row) instead of scanning the
        # whole table, then constant-time compare the full token hash.
        if not raw_token.startswith("pqkms_"):
            return None
        parts = raw_token.split("_", 2)
        if len(parts) != 3 or not parts[1] or not parts[2]:
            return None
        tid_prefix = parts[1]
        h = _hash_token(raw_token)
        rows = self.repo.find_active_tokens_by_id_prefix(tid_prefix)
        now = datetime.now(timezone.utc)
        for r in rows:
            if not secrets.compare_digest(r["token_hash"], h):
                continue
            exp = r["expires_at"]
            if exp is not None and now >= datetime.fromisoformat(exp):
                return None
            if r.get("principal_disabled"):
                return None
            return Caller(
                principal_id=r.get("principal_id"),
                display_name=r.get("display_name"),
                scopes=set(r["scopes"].split(",")),
            )
        return None

    def verify(self, raw_token: str) -> Optional[set[str]]:
        """Back-compatible scope-only lookup. Prefer authenticate() for the full
        Caller identity."""
        caller = self.authenticate(raw_token)
        return caller.scopes if caller is not None else None


def require_scope(auth: TokenAuth, required: str):
    def dep(authorization: str = Header(None)) -> Caller:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing bearer token")
        token = authorization[len("Bearer "):].strip()
        caller = auth.authenticate(token)
        if caller is None:
            raise HTTPException(401, "invalid token")
        if caller.is_admin:
            return caller
        if required not in caller.scopes:
            raise HTTPException(403, f"token missing scope: {required}")
        return caller
    return dep
