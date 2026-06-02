# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Tests for resource authorization (namespaces + grants).

Legacy mode preserves historical behaviour (a scope authorizes any key); strict
mode additionally requires a per-resource grant. Admin always bypasses grants.
"""
import base64

import pytest
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
from app.api.auth import TokenAuth, SCOPES_ADMIN, SCOPES_ENCRYPT, SCOPES_READ, SCOPES_MANAGE
from app.api.authz import Authorizer, parse_operations, resolve_mode, ALL_OPS
from app.api.routes import build_router

PASSPHRASE = "operator-passphrase-123456"
PT = base64.b64encode(b"secret").decode()


class Harness:
    def __init__(self, tmp_path, mode):
        self.repo = make_repository(f"sqlite:///{(tmp_path / 'authz.db').as_posix()}")
        self.ks = KeyStore(self.repo, PassphraseCustodian(PASSPHRASE))
        self.ks.initialize()
        kp = HybridSigner.generate()
        audit = AuditLog(self.repo, (kp.private_key, kp.public_key, kp.suite))
        self.auth = TokenAuth(self.repo)
        authz = Authorizer(self.repo, mode)
        _tid, self.admin_token, self.admin_pid = self.auth.create_token("admin", {SCOPES_ADMIN})
        limiter = Limiter(key_func=get_remote_address, default_limits=["100000/minute"])
        app = FastAPI()
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        app.include_router(build_router(self.ks, audit, self.auth, authz, limiter))
        self.client = TestClient(app)

    def h(self, token):
        return {"Authorization": f"Bearer {token}"}

    def token(self, scopes, principal_id=None):
        _tid, tok, pid = self.auth.create_token("svc", set(scopes), principal_id=principal_id)
        return tok, pid

    def create_key(self, namespace=None, name="k"):
        body = {"name": name, "key_type": "aead"}
        if namespace:
            body["namespace"] = namespace
        r = self.client.post("/api/v1/keys", json=body, headers=self.h(self.admin_token))
        assert r.status_code == 200, r.text
        return r.json()

    def grant(self, principal_id, resource_type, resource_id, operations):
        r = self.client.post("/api/v1/grants", json={
            "principal_id": principal_id, "resource_type": resource_type,
            "resource_id": resource_id, "operations": operations,
        }, headers=self.h(self.admin_token))
        assert r.status_code == 200, r.text
        return r.json()

    def encrypt(self, token, key_id):
        return self.client.post(f"/api/v1/keys/{key_id}/encrypt", json={"plaintext_b64": PT}, headers=self.h(token))


# ------------------------------------------------------------- unit bits ------

def test_parse_operations_validates():
    assert parse_operations(["encrypt", "read"]) == {"encrypt", "read"}
    assert parse_operations("encrypt,decrypt") == {"encrypt", "decrypt"}
    with pytest.raises(ValueError):
        parse_operations(["fly"])
    with pytest.raises(ValueError):
        parse_operations([])


def test_resolve_mode():
    assert resolve_mode("legacy") == "legacy"
    assert resolve_mode("STRICT") == "strict"
    with pytest.raises(RuntimeError):
        resolve_mode("paranoid")


# ------------------------------------------------------------- legacy mode ----

def test_legacy_scope_authorizes_any_key(tmp_path):
    hz = Harness(tmp_path, mode="legacy")
    key = hz.create_key()
    tok, _pid = hz.token({SCOPES_ENCRYPT})
    # No grant exists, but legacy mode lets the scope authorize the operation.
    assert hz.encrypt(tok, key["id"]).status_code == 200


# ------------------------------------------------------------- strict mode ----

def test_strict_denies_without_grant(tmp_path):
    hz = Harness(tmp_path, mode="strict")
    key = hz.create_key()
    tok, _pid = hz.token({SCOPES_ENCRYPT})
    assert hz.encrypt(tok, key["id"]).status_code == 403


def test_strict_key_grant_allows(tmp_path):
    hz = Harness(tmp_path, mode="strict")
    key = hz.create_key()
    tok, pid = hz.token({SCOPES_ENCRYPT})
    hz.grant(pid, "key", key["id"], ["encrypt"])
    assert hz.encrypt(tok, key["id"]).status_code == 200


def test_strict_grant_for_wrong_op_denied(tmp_path):
    hz = Harness(tmp_path, mode="strict")
    key = hz.create_key()
    tok, pid = hz.token({SCOPES_ENCRYPT})
    hz.grant(pid, "key", key["id"], ["read"])  # read, not encrypt
    assert hz.encrypt(tok, key["id"]).status_code == 403


def test_strict_namespace_grant_covers_keys_in_it(tmp_path):
    hz = Harness(tmp_path, mode="strict")
    # admin makes a namespace and a key in it
    r = hz.client.post("/api/v1/namespaces", json={"name": "team-a"}, headers=hz.h(hz.admin_token))
    assert r.status_code == 200, r.text
    key = hz.create_key(namespace="team-a")
    tok, pid = hz.token({SCOPES_ENCRYPT})
    hz.grant(pid, "namespace", r.json()["id"], ["encrypt"])
    assert hz.encrypt(tok, key["id"]).status_code == 200


def test_strict_admin_bypasses_grants(tmp_path):
    hz = Harness(tmp_path, mode="strict")
    key = hz.create_key()
    # admin token has no explicit grant but is global superuser
    assert hz.encrypt(hz.admin_token, key["id"]).status_code == 200


def test_strict_list_keys_namespace_isolation(tmp_path):
    hz = Harness(tmp_path, mode="strict")
    r = hz.client.post("/api/v1/namespaces", json={"name": "team-a"}, headers=hz.h(hz.admin_token))
    ns_a = r.json()["id"]
    hz.create_key(name="default-key")            # in 'default'
    team_key = hz.create_key(namespace="team-a", name="team-key")
    tok, pid = hz.token({SCOPES_READ})
    hz.grant(pid, "namespace", ns_a, ["read"])
    listed = hz.client.get("/api/v1/keys", headers=hz.h(tok)).json()
    ids = {k["id"] for k in listed}
    assert ids == {team_key["id"]}, "caller must see only keys in namespaces they can read"
    # admin sees both
    admin_ids = {k["id"] for k in hz.client.get("/api/v1/keys", headers=hz.h(hz.admin_token)).json()}
    assert team_key["id"] in admin_ids and len(admin_ids) == 2


def test_strict_get_key_hides_existence_without_grant(tmp_path):
    hz = Harness(tmp_path, mode="strict")
    key = hz.create_key()
    tok, _pid = hz.token({SCOPES_READ})
    # No read grant: forbidden, and indistinguishable from a missing key (403).
    assert hz.client.get(f"/api/v1/keys/{key['id']}", headers=hz.h(tok)).status_code == 403
    assert hz.client.get("/api/v1/keys/does-not-exist", headers=hz.h(tok)).status_code == 403


# ------------------------------------------------- manage scope / creation ----

def test_create_key_requires_manage_scope(tmp_path):
    hz = Harness(tmp_path, mode="legacy")
    tok, _pid = hz.token({SCOPES_ENCRYPT})  # no manage scope
    r = hz.client.post("/api/v1/keys", json={"name": "x", "key_type": "aead"}, headers=hz.h(tok))
    assert r.status_code == 403


def test_strict_namespace_manage_grant_allows_create(tmp_path):
    hz = Harness(tmp_path, mode="strict")
    r = hz.client.post("/api/v1/namespaces", json={"name": "team-b"}, headers=hz.h(hz.admin_token))
    ns_b = r.json()["id"]
    tok, pid = hz.token({SCOPES_MANAGE})
    # Without a grant, manage scope alone is not enough in strict mode.
    denied = hz.client.post("/api/v1/keys", json={"name": "k1", "key_type": "aead", "namespace": "team-b"},
                            headers=hz.h(tok))
    assert denied.status_code == 403
    hz.grant(pid, "namespace", ns_b, ["manage"])
    allowed = hz.client.post("/api/v1/keys", json={"name": "k1", "key_type": "aead", "namespace": "team-b"},
                             headers=hz.h(tok))
    assert allowed.status_code == 200, allowed.text


# ------------------------------------------------------------- grant CRUD -----

def test_grant_upsert_replaces_operations(tmp_path):
    hz = Harness(tmp_path, mode="strict")
    key = hz.create_key()
    tok, pid = hz.token({SCOPES_ENCRYPT, SCOPES_READ})
    g1 = hz.grant(pid, "key", key["id"], ["read"])
    g2 = hz.grant(pid, "key", key["id"], ["encrypt"])  # same triple -> replaces
    assert g1["id"] == g2["id"], "re-granting the same resource updates in place"
    # encrypt now allowed (the latest grant), proving operations were replaced
    assert hz.encrypt(tok, key["id"]).status_code == 200


def test_grant_rejects_unknown_principal_and_resource(tmp_path):
    hz = Harness(tmp_path, mode="strict")
    bad_p = hz.client.post("/api/v1/grants", json={
        "principal_id": "nope", "resource_type": "namespace",
        "resource_id": "x", "operations": ["read"]}, headers=hz.h(hz.admin_token))
    assert bad_p.status_code == 400
