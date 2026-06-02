# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Signed session cookies for browser (human-operator) sessions established via
OIDC SSO. Machine clients use bearer tokens and never touch this.

A session is a compact, HMAC-SHA256-signed token: base64url(payload).base64url(sig).
The payload carries the principal id, granted scopes, the IdP subject, and an
absolute expiry. It is stateless (no server-side session store) and
tamper-evident — any modification invalidates the signature. The signing key is
PQKMS_SESSION_SECRET (or a random per-process key as a dev fallback; set it
explicitly so sessions survive restarts and are shared across replicas).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Optional

SESSION_COOKIE = "pqkms_session"
OIDC_TX_COOKIE = "pqkms_oidc_tx"
DEFAULT_TTL_SECONDS = 8 * 3600


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


class SessionManager:
    def __init__(self, secret: bytes, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        if not secret:
            raise ValueError("session secret must be non-empty")
        self._secret = secret
        self.ttl_seconds = ttl_seconds

    @classmethod
    def from_secret_str(cls, secret: Optional[str], ttl_seconds: int = DEFAULT_TTL_SECONDS) -> "SessionManager":
        if secret:
            key = hashlib.sha256(secret.encode("utf-8")).digest()
        else:
            # Dev fallback: ephemeral key. Sessions won't survive a restart and
            # won't validate across replicas — set PQKMS_SESSION_SECRET in prod.
            key = secrets.token_bytes(32)
        return cls(key, ttl_seconds=ttl_seconds)

    def _sign(self, payload_b: bytes) -> str:
        sig = hmac.new(self._secret, payload_b, hashlib.sha256).digest()
        return f"{_b64u(payload_b)}.{_b64u(sig)}"

    def _unsign(self, value: str) -> Optional[bytes]:
        try:
            payload_part, sig_part = value.split(".", 1)
            payload_b = _b64u_decode(payload_part)
            expected = hmac.new(self._secret, payload_b, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, _b64u_decode(sig_part)):
                return None
            return payload_b
        except Exception:
            return None

    def issue(self, principal_id: str, scopes: set[str], sub: str, *, now: Optional[int] = None) -> str:
        now = int(now if now is not None else time.time())
        payload = {
            "pid": principal_id,
            "scopes": sorted(scopes),
            "sub": sub,
            "exp": now + self.ttl_seconds,
        }
        return self._sign(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))

    def verify(self, value: str, *, now: Optional[int] = None) -> Optional[dict]:
        payload_b = self._unsign(value)
        if payload_b is None:
            return None
        try:
            payload = json.loads(payload_b)
        except ValueError:
            return None
        now = int(now if now is not None else time.time())
        if not isinstance(payload, dict) or "exp" not in payload or now >= int(payload["exp"]):
            return None
        return {
            "principal_id": payload.get("pid"),
            "scopes": set(payload.get("scopes", [])),
            "sub": payload.get("sub"),
        }

    # Short-lived signed value for the OIDC login transaction (state/nonce/PKCE).
    def sign_tx(self, data: dict, *, now: Optional[int] = None) -> str:
        now = int(now if now is not None else time.time())
        data = {**data, "exp": now + 600}  # 10 minutes to complete login
        return self._sign(json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8"))

    def verify_tx(self, value: str, *, now: Optional[int] = None) -> Optional[dict]:
        payload_b = self._unsign(value)
        if payload_b is None:
            return None
        try:
            data = json.loads(payload_b)
        except ValueError:
            return None
        now = int(now if now is not None else time.time())
        if not isinstance(data, dict) or now >= int(data.get("exp", 0)):
            return None
        return data
