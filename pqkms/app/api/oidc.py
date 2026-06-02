# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
OIDC (OpenID Connect) authorization-code + PKCE login for human operators.

Opt-in via PQKMS_OIDC_ENABLED. When enabled the UI authenticates operators
against an external IdP (Okta, Entra ID, Keycloak, Google, …) instead of pasting
a bootstrap token; machine clients keep using bearer tokens. The id_token
signature is verified against the IdP's JWKS, and issuer/audience/expiry/nonce
are all checked. Group claims map to scopes (admin group -> admin scope).

The IdP interactions (discovery, token exchange, JWKS) go through small seams
that tests inject, so the verification logic is exercised without a live IdP.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass, field
from typing import Optional

from .auth import ALL_SCOPES, SCOPES_ADMIN, SCOPES_READ


def _truthy(val: "str | None") -> bool:
    return bool(val) and val.strip().lower() not in ("0", "false", "no", "off", "")


def _csv_env(name: str) -> set[str]:
    raw = os.environ.get(name, "")
    return {x.strip() for x in raw.split(",") if x.strip()}


@dataclass
class OidcConfig:
    enabled: bool
    issuer: str = ""
    client_id: str = ""
    client_secret: str = ""
    redirect_url: str = ""
    scopes: str = "openid email profile"
    groups_claim: str = "groups"
    admin_groups: set[str] = field(default_factory=set)
    default_scopes: set[str] = field(default_factory=lambda: {SCOPES_READ})

    @classmethod
    def from_env(cls) -> "OidcConfig":
        enabled = _truthy(os.environ.get("PQKMS_OIDC_ENABLED"))
        if not enabled:
            return cls(enabled=False)
        issuer = os.environ.get("PQKMS_OIDC_ISSUER", "").rstrip("/")
        client_id = os.environ.get("PQKMS_OIDC_CLIENT_ID", "")
        client_secret = os.environ.get("PQKMS_OIDC_CLIENT_SECRET", "")
        redirect_url = os.environ.get("PQKMS_OIDC_REDIRECT_URL", "")
        missing = [n for n, v in [
            ("PQKMS_OIDC_ISSUER", issuer), ("PQKMS_OIDC_CLIENT_ID", client_id),
            ("PQKMS_OIDC_CLIENT_SECRET", client_secret), ("PQKMS_OIDC_REDIRECT_URL", redirect_url),
        ] if not v]
        if missing:
            raise RuntimeError(f"PQKMS_OIDC_ENABLED is set but missing: {', '.join(missing)}")
        default_scopes = _csv_env("PQKMS_OIDC_DEFAULT_SCOPES") or {SCOPES_READ}
        bad = default_scopes - ALL_SCOPES
        if bad:
            raise RuntimeError(f"PQKMS_OIDC_DEFAULT_SCOPES has unknown scopes: {sorted(bad)}")
        return cls(
            enabled=True, issuer=issuer, client_id=client_id, client_secret=client_secret,
            redirect_url=redirect_url,
            scopes=os.environ.get("PQKMS_OIDC_SCOPES", "openid email profile"),
            groups_claim=os.environ.get("PQKMS_OIDC_GROUPS_CLAIM", "groups"),
            admin_groups=_csv_env("PQKMS_OIDC_ADMIN_GROUPS"),
            default_scopes=default_scopes,
        )


def make_pkce() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for PKCE S256."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return verifier, challenge


class OidcError(Exception):
    """OIDC login failure (verification or IdP error). Surfaced as a 401/502."""


class OidcClient:
    """Thin OIDC client. `discovery` and `jwks` may be injected (tests / caching);
    otherwise they are fetched lazily via httpx from the issuer."""

    def __init__(self, config: OidcConfig, *, http=None, discovery: Optional[dict] = None,
                 jwks: Optional[dict] = None):
        self.config = config
        self._http = http
        self._discovery = discovery
        self._jwks = jwks

    # ---- IdP metadata (lazy, cached) ----

    def _client(self):
        if self._http is not None:
            return self._http
        import httpx
        self._http = httpx.Client(timeout=10.0)
        return self._http

    def discovery(self) -> dict:
        if self._discovery is None:
            url = f"{self.config.issuer}/.well-known/openid-configuration"
            resp = self._client().get(url)
            resp.raise_for_status()
            self._discovery = resp.json()
        return self._discovery

    def _jwks_doc(self) -> dict:
        if self._jwks is None:
            resp = self._client().get(self.discovery()["jwks_uri"])
            resp.raise_for_status()
            self._jwks = resp.json()
        return self._jwks

    # ---- flow ----

    def authorization_url(self, state: str, nonce: str, code_challenge: str) -> str:
        from urllib.parse import urlencode
        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_url,
            "scope": self.config.scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{self.discovery()['authorization_endpoint']}?{urlencode(params)}"

    def exchange_code(self, code: str, code_verifier: str) -> dict:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.config.redirect_url,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "code_verifier": code_verifier,
        }
        resp = self._client().post(self.discovery()["token_endpoint"], data=data)
        if resp.status_code != 200:
            raise OidcError(f"token endpoint returned {resp.status_code}")
        return resp.json()

    def verify_id_token(self, id_token: str, expected_nonce: str) -> dict:
        import jwt
        from jwt import PyJWKClient, PyJWK

        try:
            header = jwt.get_unverified_header(id_token)
            kid = header.get("kid")
            alg = header.get("alg", "RS256")
            if self._jwks is not None:
                key = None
                for k in self._jwks.get("keys", []):
                    if k.get("kid") == kid or kid is None:
                        key = PyJWK.from_dict(k).key
                        break
                if key is None:
                    raise OidcError("no matching JWKS key for id_token")
            else:
                key = PyJWKClient(self.discovery()["jwks_uri"]).get_signing_key_from_jwt(id_token).key
            claims = jwt.decode(
                id_token, key, algorithms=[alg],
                audience=self.config.client_id, issuer=self.config.issuer,
                options={"require": ["exp", "iat", "aud", "iss"]},
            )
        except OidcError:
            raise
        except Exception as e:
            raise OidcError(f"id_token verification failed: {e}") from e
        if expected_nonce and claims.get("nonce") != expected_nonce:
            raise OidcError("id_token nonce mismatch")
        return claims

    def claims_to_scopes(self, claims: dict) -> set[str]:
        groups = claims.get(self.config.groups_claim) or []
        if isinstance(groups, str):
            groups = [groups]
        if self.config.admin_groups and (set(groups) & self.config.admin_groups):
            return {SCOPES_ADMIN}
        return set(self.config.default_scopes)
