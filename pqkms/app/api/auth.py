# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Token authentication. Tokens are stored as SHA-384 hashes; the raw token is
only returned once at creation time. Scopes control what each token can do.
"""
import hashlib
import secrets
import uuid
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


def _hash_token(token: str) -> bytes:
    return hashlib.sha384(token.encode()).digest()


class TokenAuth:
    def __init__(self, repo: Repository):
        self.repo = repo

    def has_any_token(self) -> bool:
        return self.repo.has_any_token()

    def create_token(
        self,
        name: str,
        scopes: set[str],
        ttl_seconds: Optional[int] = None,
    ) -> tuple[str, str]:
        bad = scopes - ALL_SCOPES
        if bad:
            raise ValueError(f"unknown scopes: {bad}")
        tid = str(uuid.uuid4())
        raw = secrets.token_urlsafe(32)
        formatted = f"pqkms_{tid[:8]}_{raw}"
        now = datetime.now(timezone.utc)
        expires_at = None
        if ttl_seconds is not None:
            if ttl_seconds <= 0:
                raise ValueError("ttl_seconds must be positive")
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
        })
        return tid, formatted

    def revoke(self, token_id: str):
        self.repo.revoke_token(token_id)

    def list_tokens(self) -> list[dict]:
        return self.repo.list_tokens()

    def verify(self, raw_token: str) -> Optional[set[str]]:
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
            return set(r["scopes"].split(","))
        return None


def require_scope(auth: TokenAuth, required: str):
    def dep(authorization: str = Header(None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing bearer token")
        token = authorization[len("Bearer "):].strip()
        scopes = auth.verify(token)
        if scopes is None:
            raise HTTPException(401, "invalid token")
        if SCOPES_ADMIN in scopes:
            return scopes
        if required not in scopes:
            raise HTTPException(403, f"token missing scope: {required}")
        return scopes
    return dep
