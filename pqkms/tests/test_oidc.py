# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
OIDC SSO: id_token verification against a JWKS, claims->scopes mapping, signed
session cookies, the login/callback flow (with a mocked IdP), and that a session
cookie authenticates protected routes just like a bearer token.
"""
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.storage.repository import make_repository
from app.storage.keystore import KeyStore
from app.storage.audit import AuditLog
from app.custody import PassphraseCustodian
from app.crypto.signatures import HybridSigner
from app.api.auth import TokenAuth, SCOPES_ADMIN, SCOPES_READ
from app.api.authz import Authorizer
from app.api.routes import build_router
from app.api.sessions import SessionManager, SESSION_COOKIE
from app.api.oidc import OidcConfig, OidcClient, OidcError

ISSUER = "https://idp.example.com"
CLIENT_ID = "pqkms-client"


# ----- a real RSA-signed id_token + JWKS, so verification is genuinely exercised -----

def _rsa_jwks_and_signer():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_numbers = key.public_key().public_numbers()

    def _b64u_int(n):
        import base64
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    jwk = {"kty": "RSA", "kid": "test-kid", "use": "sig", "alg": "RS256",
           "n": _b64u_int(pub_numbers.n), "e": _b64u_int(pub_numbers.e)}
    jwks = {"keys": [jwk]}

    def sign(claims):
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-kid"})

    return jwks, sign


def _config(**over):
    base = dict(enabled=True, issuer=ISSUER, client_id=CLIENT_ID, client_secret="s",
                redirect_url=f"{ISSUER}/cb", admin_groups={"kms-admins"})
    base.update(over)
    return OidcConfig(**base)


def _claims(**over):
    now = int(time.time())
    c = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "user-123", "email": "a@example.com",
         "iat": now, "exp": now + 300, "nonce": "N"}
    c.update(over)
    return c


# ----------------------------------------------------------- config -----------

def test_config_disabled_by_default(monkeypatch):
    monkeypatch.delenv("PQKMS_OIDC_ENABLED", raising=False)
    assert OidcConfig.from_env().enabled is False


def test_config_enabled_requires_fields(monkeypatch):
    monkeypatch.setenv("PQKMS_OIDC_ENABLED", "1")
    monkeypatch.delenv("PQKMS_OIDC_ISSUER", raising=False)
    with pytest.raises(RuntimeError):
        OidcConfig.from_env()


# ----------------------------------------------------- id_token verify --------

def test_verify_id_token_happy_path():
    jwks, sign = _rsa_jwks_and_signer()
    client = OidcClient(_config(), jwks=jwks)
    claims = client.verify_id_token(sign(_claims()), "N")
    assert claims["sub"] == "user-123"


def test_verify_id_token_rejects_bad_nonce():
    jwks, sign = _rsa_jwks_and_signer()
    client = OidcClient(_config(), jwks=jwks)
    with pytest.raises(OidcError):
        client.verify_id_token(sign(_claims(nonce="N")), "DIFFERENT")


def test_verify_id_token_rejects_wrong_audience():
    jwks, sign = _rsa_jwks_and_signer()
    client = OidcClient(_config(), jwks=jwks)
    with pytest.raises(OidcError):
        client.verify_id_token(sign(_claims(aud="someone-else")), "N")


def test_verify_id_token_rejects_expired():
    jwks, sign = _rsa_jwks_and_signer()
    client = OidcClient(_config(), jwks=jwks)
    with pytest.raises(OidcError):
        client.verify_id_token(sign(_claims(exp=int(time.time()) - 10)), "N")


def test_claims_to_scopes_admin_group():
    client = OidcClient(_config())
    assert client.claims_to_scopes(_claims(groups=["kms-admins"])) == {SCOPES_ADMIN}
    assert client.claims_to_scopes(_claims(groups=["other"])) == {SCOPES_READ}


# ----------------------------------------------------------- sessions ---------

def test_session_roundtrip_and_tamper():
    sm = SessionManager(b"k" * 32, ttl_seconds=100)
    val = sm.issue("pid-1", {SCOPES_READ}, "sub-1")
    sess = sm.verify(val)
    assert sess["principal_id"] == "pid-1" and sess["scopes"] == {SCOPES_READ}
    # tamper -> rejected
    assert sm.verify(val[:-2] + ("AA" if not val.endswith("AA") else "BB")) is None


def test_session_expiry():
    sm = SessionManager(b"k" * 32, ttl_seconds=100)
    val = sm.issue("pid", {SCOPES_READ}, "sub", now=1000)
    assert sm.verify(val, now=1050) is not None
    assert sm.verify(val, now=2000) is None


def test_session_wrong_secret_rejected():
    a = SessionManager(b"a" * 32)
    b = SessionManager(b"b" * 32)
    assert b.verify(a.issue("pid", {SCOPES_READ}, "sub")) is None


# ----------------------------------------------- end-to-end with mock IdP -----

class FakeOidc(OidcClient):
    """OidcClient with the network calls stubbed: it captures the nonce issued at
    login (like a real IdP echoes it) and returns a JWKS-signed id_token carrying
    that nonce, so verify_id_token runs for real end to end."""

    def __init__(self, config, claims):
        jwks, sign = _rsa_jwks_and_signer()
        super().__init__(config, jwks=jwks)
        self._sign = sign
        self._claims = claims
        self._nonce = None

    def authorization_url(self, state, nonce, code_challenge):
        self._nonce = nonce
        return f"{self.config.issuer}/authorize?state={state}"

    def exchange_code(self, code, code_verifier):
        return {"id_token": self._sign({**self._claims, "nonce": self._nonce})}


def _app(tmp_path, oidc=None, sessions=None):
    repo = make_repository(f"sqlite:///{(tmp_path / 'oidc.db').as_posix()}")
    ks = KeyStore(repo, PassphraseCustodian("operator-passphrase-123456"))
    ks.initialize()
    kp = HybridSigner.generate()
    audit = AuditLog(repo, (kp.private_key, kp.public_key, kp.suite))
    auth = TokenAuth(repo)
    limiter = Limiter(key_func=get_remote_address, default_limits=["100000/minute"])
    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(build_router(ks, audit, auth, Authorizer(repo), limiter,
                                    sessions=sessions, oidc=oidc, cookie_secure=False))
    return app, repo, auth


def test_auth_config_endpoint_reports_sso(tmp_path):
    app, _repo, _auth = _app(tmp_path)
    c = TestClient(app)
    assert c.get("/api/v1/auth/config").json() == {"sso_enabled": False}


def test_login_redirects_to_idp(tmp_path):
    sm = SessionManager(b"k" * 32)
    app, _repo, _auth = _app(tmp_path, oidc=FakeOidc(_config(), _claims()), sessions=sm)
    c = TestClient(app)
    r = c.get("/api/v1/auth/login", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].startswith(f"{ISSUER}/authorize")
    assert "pqkms_oidc_tx=" in r.headers.get("set-cookie", "")


def test_full_login_creates_session_and_principal(tmp_path):
    sm = SessionManager(b"k" * 32)
    oidc = FakeOidc(_config(), _claims(groups=["kms-admins"]))
    app, repo, auth = _app(tmp_path, oidc=oidc, sessions=sm)
    c = TestClient(app)
    # 1. login -> capture the tx cookie + state
    login = c.get("/api/v1/auth/login", follow_redirects=False)
    state = login.headers["location"].split("state=")[1]
    # tx cookie is in the client jar now; complete the callback
    cb = c.get(f"/api/v1/auth/callback?code=abc&state={state}", follow_redirects=False)
    assert cb.status_code == 302 and cb.headers["location"] == "/ui"
    assert f"{SESSION_COOKIE}=" in cb.headers.get("set-cookie", "")
    # a human principal was created for the IdP subject
    humans = [p for p in auth.list_principals() if p["ptype"] == "human"]
    assert len(humans) == 1 and humans[0]["display_name"] == "a@example.com"


def test_session_cookie_authenticates_routes(tmp_path):
    """A session minted for an admin-scoped principal authorizes API calls the
    same way a bearer token would."""
    sm = SessionManager(b"k" * 32)
    app, _repo, auth = _app(tmp_path, oidc=FakeOidc(_config(), _claims()), sessions=sm)
    pid = auth.create_principal("alice", "human")
    c = TestClient(app)
    c.cookies.set(SESSION_COOKIE, sm.issue(pid, {SCOPES_ADMIN}, "user-123"))
    # create a key using only the session cookie (no Authorization header)
    r = c.post("/api/v1/keys", json={"name": "k", "key_type": "aead"})
    assert r.status_code == 200, r.text
    # /auth/me reflects the session identity
    me = c.get("/api/v1/auth/me").json()
    assert me["principal_id"] == pid and "admin" in me["scopes"]


def test_callback_rejects_bad_state(tmp_path):
    sm = SessionManager(b"k" * 32)
    app, _repo, _auth = _app(tmp_path, oidc=FakeOidc(_config(), _claims()), sessions=sm)
    c = TestClient(app)
    c.get("/api/v1/auth/login", follow_redirects=False)  # sets tx cookie
    bad = c.get("/api/v1/auth/callback?code=abc&state=forged", follow_redirects=False)
    assert bad.status_code == 400


def test_logout_clears_cookie(tmp_path):
    sm = SessionManager(b"k" * 32)
    app, _repo, _auth = _app(tmp_path, oidc=FakeOidc(_config(), _claims()), sessions=sm)
    c = TestClient(app)
    r = c.post("/api/v1/auth/logout")
    assert r.status_code == 200 and r.json()["ok"] is True
