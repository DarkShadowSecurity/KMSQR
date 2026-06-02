# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Tests for principals: every token authenticates as a stable principal, and the
audit log attributes actions to that principal id (not an anonymous scope string).
Also covers the Alembic backfill that gives pre-existing tokens a principal.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import create_engine, text

from app.storage.repository import make_repository
from app.storage.keystore import KeyStore
from app.storage.audit import AuditLog
from app.storage.migrate import run_migrations
from app.custody import PassphraseCustodian
from app.crypto.signatures import HybridSigner
from app.api.auth import TokenAuth, SCOPES_ADMIN, SCOPES_READ
from app.api.authz import Authorizer
from app.api.routes import build_router


def _repo(tmp_path, name="test.db"):
    return make_repository(f"sqlite:///{(tmp_path / name).as_posix()}")


@pytest.fixture
def auth(tmp_path):
    return TokenAuth(_repo(tmp_path))


# ---------------------------------------------------------- principal model ----

def test_token_creates_and_binds_principal(auth):
    tid, tok, pid = auth.create_token("svc-a", {SCOPES_ADMIN})
    caller = auth.authenticate(tok)
    assert caller is not None
    assert caller.principal_id == pid
    assert caller.display_name == "svc-a"
    assert caller.scopes == {SCOPES_ADMIN}
    # The audit actor string is derived from the principal, not the scopes.
    assert caller.actor == f"principal:{pid}"
    assert auth.get_principal(pid)["display_name"] == "svc-a"


def test_multiple_tokens_can_share_one_principal(auth):
    pid = auth.create_principal("ci-runner", "service")
    _t1id, t1, p1 = auth.create_token("ci-token-1", {SCOPES_READ}, principal_id=pid)
    _t2id, t2, p2 = auth.create_token("ci-token-2", {SCOPES_READ}, principal_id=pid)
    assert p1 == p2 == pid
    assert auth.authenticate(t1).principal_id == pid
    assert auth.authenticate(t2).principal_id == pid


def test_token_for_unknown_principal_rejected(auth):
    with pytest.raises(ValueError):
        auth.create_token("x", {SCOPES_READ}, principal_id="no-such-principal")


def test_unknown_principal_type_rejected(auth):
    with pytest.raises(ValueError):
        auth.create_principal("x", "robot")


def test_disabled_principal_blocks_its_tokens(auth):
    _tid, tok, pid = auth.create_token("svc", {SCOPES_READ})
    assert auth.authenticate(tok) is not None
    auth.set_principal_disabled(pid, True)
    assert auth.authenticate(tok) is None, "a disabled principal's tokens must not authenticate"
    auth.set_principal_disabled(pid, False)
    assert auth.authenticate(tok) is not None


def test_delete_principal_revokes_tokens(auth):
    _tid, tok, pid = auth.create_token("svc", {SCOPES_READ})
    assert auth.delete_principal(pid) is True
    assert auth.authenticate(tok) is None, "deleting a principal must invalidate its tokens"
    assert auth.get_principal(pid) is None
    assert auth.delete_principal(pid) is False  # idempotent: already gone


# ------------------------------------------------------------- migration ------

def test_legacy_token_backfilled_with_principal(tmp_path):
    """A database created by a pre-Alembic build (original tables, no
    alembic_version) is stamped + upgraded, and each legacy token gets its own
    service principal so its actions become attributable."""
    url = f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}"
    engine = create_engine(url, future=True)
    with engine.begin() as c:
        c.execute(text("CREATE TABLE kms_meta (k TEXT PRIMARY KEY, v BLOB NOT NULL)"))
        c.execute(text(
            "CREATE TABLE managed_keys (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, "
            "key_type TEXT NOT NULL, current_version INTEGER NOT NULL, created_at TEXT NOT NULL, description TEXT)"
        ))
        c.execute(text(
            "CREATE TABLE key_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, key_id TEXT NOT NULL, "
            "version INTEGER NOT NULL, suite INTEGER NOT NULL, wrapped_secret BLOB NOT NULL, "
            "public_material BLOB, created_at TEXT NOT NULL, state TEXT NOT NULL, usage_count BIGINT NOT NULL DEFAULT 0)"
        ))
        c.execute(text(
            "CREATE TABLE audit_log (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, "
            "action TEXT NOT NULL, target TEXT, detail TEXT, prev_hash BLOB NOT NULL, entry_hash BLOB NOT NULL, signature BLOB NOT NULL)"
        ))
        c.execute(text(
            "CREATE TABLE api_tokens (id TEXT PRIMARY KEY, token_hash BLOB NOT NULL, name TEXT NOT NULL, "
            "scopes TEXT NOT NULL, created_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, expires_at TEXT)"
        ))
        c.execute(text(
            "INSERT INTO api_tokens VALUES ('tid-1', X'00', 'legacy-svc', 'admin', '2026-01-01T00:00:00Z', 0, NULL)"
        ))

    run_migrations(engine)

    with engine.connect() as c:
        assert c.exec_driver_sql("SELECT version_num FROM alembic_version").fetchone()[0] == "0003"
        pid = c.exec_driver_sql("SELECT principal_id FROM api_tokens WHERE id='tid-1'").fetchone()[0]
        assert pid, "legacy token must be linked to a backfilled principal"
        name = c.exec_driver_sql("SELECT display_name FROM principals WHERE id=:p", {"p": pid}).fetchone()[0]
        assert name == "legacy-svc"


# ------------------------------------------------------- audit attribution ----

def _app(tmp_path):
    repo = _repo(tmp_path)
    ks = KeyStore(repo, PassphraseCustodian("operator-passphrase-123456"))
    ks.initialize()
    kp = HybridSigner.generate()
    audit = AuditLog(repo, (kp.private_key, kp.public_key, kp.suite))
    auth = TokenAuth(repo)
    _tid, tok, pid = auth.create_token("admin", {SCOPES_ADMIN})
    limiter = Limiter(key_func=get_remote_address, default_limits=["10000/minute"])
    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(build_router(ks, audit, auth, Authorizer(repo), limiter))
    return app, tok, pid


def test_audit_actor_is_principal_end_to_end(tmp_path):
    app, tok, pid = _app(tmp_path)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {tok}"}

    r = client.post("/api/v1/keys", json={"name": "k1", "key_type": "aead"}, headers=headers)
    assert r.status_code == 200, r.text

    entries = client.get("/api/v1/audit", headers=headers).json()["entries"]
    create_actors = {e["actor"] for e in entries if e["action"] == "key.create"}
    assert create_actors == {f"principal:{pid}"}, (
        "key.create must be attributed to the calling principal, not token[scopes]"
    )
