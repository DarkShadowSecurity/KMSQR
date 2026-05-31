# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Token authentication. Tokens are stored as SHA-384 hashes; the raw token is
only returned once at creation time. Scopes control what each token can do.
"""
import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import HTTPException, Header

from ..storage.db import Database


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
    def __init__(self, db: Database):
        self.db = db

    def has_any_token(self) -> bool:
        return self.db.conn().execute(
            "SELECT 1 FROM api_tokens WHERE revoked=0 LIMIT 1"
        ).fetchone() is not None

    def create_token(self, name: str, scopes: set[str]) -> tuple[str, str]:
        bad = scopes - ALL_SCOPES
        if bad:
            raise ValueError(f"unknown scopes: {bad}")
        tid = str(uuid.uuid4())
        raw = secrets.token_urlsafe(32)
        formatted = f"pqkms_{tid[:8]}_{raw}"
        # Hash the formatted token — that's what verify() will see on the wire.
        self.db.conn().execute(
            "INSERT INTO api_tokens(id,token_hash,name,scopes,created_at,revoked) VALUES(?,?,?,?,?,0)",
            (tid, _hash_token(formatted), name, ",".join(sorted(scopes)), datetime.now(timezone.utc).isoformat()),
        )
        return tid, formatted

    def revoke(self, token_id: str):
        self.db.conn().execute("UPDATE api_tokens SET revoked=1 WHERE id=?", (token_id,))

    def list_tokens(self) -> list[dict]:
        rows = self.db.conn().execute(
            "SELECT id,name,scopes,created_at,revoked FROM api_tokens ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def verify(self, raw_token: str) -> Optional[set[str]]:
        # tokens look like pqkms_<tid_prefix>_<secret>
        if not raw_token.startswith("pqkms_"):
            return None
        rows = self.db.conn().execute(
            "SELECT token_hash, scopes FROM api_tokens WHERE revoked=0"
        ).fetchall()
        h = _hash_token(raw_token)
        for r in rows:
            if secrets.compare_digest(bytes(r["token_hash"]), h):
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
