# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Key lifecycle: enable/disable, scheduled deletion + cancel + destroy, BYOK import,
public-key export, and the rule that non-enabled keys refuse crypto operations.
"""
import base64

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.storage.repository import make_repository
from app.storage.keystore import KeyStore, KeyStateError, KEY_ENABLED, KEY_DISABLED, KEY_PENDING_DELETION
from app.storage.audit import AuditLog
from app.custody import PassphraseCustodian
from app.crypto.signatures import HybridSigner
from app.crypto.aead import AEAD
from app.api.auth import TokenAuth, SCOPES_ADMIN
from app.api.authz import Authorizer
from app.api.routes import build_router

PT = base64.b64encode(b"secret").decode()


class Harness:
    def __init__(self, tmp_path):
        self.repo = make_repository(f"sqlite:///{(tmp_path / 'lc.db').as_posix()}")
        self.ks = KeyStore(self.repo, PassphraseCustodian("operator-passphrase-123456"))
        self.ks.initialize()
        kp = HybridSigner.generate()
        audit = AuditLog(self.repo, (kp.private_key, kp.public_key, kp.suite))
        self.auth = TokenAuth(self.repo)
        _t, self.admin, _p = self.auth.create_token("admin", {SCOPES_ADMIN})
        limiter = Limiter(key_func=get_remote_address, default_limits=["100000/minute"])
        app = FastAPI()
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        app.include_router(build_router(self.ks, audit, self.auth, Authorizer(self.repo), limiter))
        self.client = TestClient(app)

    def h(self):
        return {"Authorization": f"Bearer {self.admin}"}

    def create(self, key_type="aead", name="k"):
        r = self.client.post("/api/v1/keys", json={"name": name, "key_type": key_type}, headers=self.h())
        assert r.status_code == 200, r.text
        return r.json()

    def post(self, path, json=None):
        return self.client.post(path, json=json or {}, headers=self.h())


# --------------------------------------------------------- KeyStore unit ------

def test_disabled_key_refuses_crypto(tmp_path):
    hz = Harness(tmp_path)
    key = hz.create()
    # works while enabled
    assert hz.post(f"/api/v1/keys/{key['id']}/encrypt", {"plaintext_b64": PT}).status_code == 200
    assert hz.post(f"/api/v1/keys/{key['id']}/disable").status_code == 200
    # refused while disabled -> 409
    r = hz.post(f"/api/v1/keys/{key['id']}/encrypt", {"plaintext_b64": PT})
    assert r.status_code == 409, r.text
    # re-enable restores it
    assert hz.post(f"/api/v1/keys/{key['id']}/enable").status_code == 200
    assert hz.post(f"/api/v1/keys/{key['id']}/encrypt", {"plaintext_b64": PT}).status_code == 200


def test_disabled_key_cannot_decrypt(tmp_path):
    hz = Harness(tmp_path)
    key = hz.create()
    ct = hz.post(f"/api/v1/keys/{key['id']}/encrypt", {"plaintext_b64": PT}).json()["ciphertext"]
    hz.post(f"/api/v1/keys/{key['id']}/disable")
    r = hz.post(f"/api/v1/keys/{key['id']}/decrypt", {"ciphertext_b64": ct})
    assert r.status_code == 409


def test_schedule_cancel_deletion(tmp_path):
    hz = Harness(tmp_path)
    key = hz.create()
    sd = hz.post(f"/api/v1/keys/{key['id']}/schedule-deletion", {"window_days": 30})
    assert sd.status_code == 200
    assert sd.json()["state"] == KEY_PENDING_DELETION
    assert sd.json()["deletion_at"] is not None
    # pending key refuses crypto
    assert hz.post(f"/api/v1/keys/{key['id']}/encrypt", {"plaintext_b64": PT}).status_code == 409
    # cancel -> disabled
    cd = hz.post(f"/api/v1/keys/{key['id']}/cancel-deletion")
    assert cd.status_code == 200 and cd.json()["state"] == KEY_DISABLED


def test_destroy_blocked_until_window_elapses(tmp_path):
    hz = Harness(tmp_path)
    key = hz.create()
    # not pending -> cannot destroy without force
    assert hz.client.delete(f"/api/v1/keys/{key['id']}", headers=hz.h()).status_code == 409
    hz.post(f"/api/v1/keys/{key['id']}/schedule-deletion", {"window_days": 30})
    # pending but window not elapsed -> still blocked
    assert hz.client.delete(f"/api/v1/keys/{key['id']}", headers=hz.h()).status_code == 409


def test_destroy_immediate_with_zero_window(tmp_path):
    hz = Harness(tmp_path)
    key = hz.create()
    hz.post(f"/api/v1/keys/{key['id']}/schedule-deletion", {"window_days": 0})
    r = hz.client.delete(f"/api/v1/keys/{key['id']}", headers=hz.h())
    assert r.status_code == 200, r.text
    # the key is gone
    assert hz.ks.get_key(key["id"]) is None


def test_force_destroy_requires_admin_and_removes_key(tmp_path):
    hz = Harness(tmp_path)
    key = hz.create()
    # admin force-destroys an enabled key directly (break-glass)
    r = hz.client.delete(f"/api/v1/keys/{key['id']}?force=true", headers=hz.h())
    assert r.status_code == 200, r.text
    assert hz.ks.get_key(key["id"]) is None


def test_byok_import_roundtrip(tmp_path):
    hz = Harness(tmp_path)
    material = AEAD.generate_key()
    r = hz.client.post("/api/v1/keys/import", json={
        "name": "byok", "key_material_b64": base64.b64encode(material).decode(),
    }, headers=hz.h())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["origin"] == "imported"
    # the imported key works for encryption
    assert hz.post(f"/api/v1/keys/{body['id']}/encrypt", {"plaintext_b64": PT}).status_code == 200


def test_byok_rejects_wrong_length(tmp_path):
    hz = Harness(tmp_path)
    r = hz.client.post("/api/v1/keys/import", json={
        "name": "bad", "key_material_b64": base64.b64encode(b"too-short").decode(),
    }, headers=hz.h())
    assert r.status_code == 400


def test_public_key_export(tmp_path):
    hz = Harness(tmp_path)
    sig = hz.create(key_type="sig", name="signer")
    r = hz.client.get(f"/api/v1/keys/{sig['id']}/public-key", headers=hz.h())
    assert r.status_code == 200, r.text
    assert r.json()["public_key_b64"]
    # AEAD keys have no public material
    aead = hz.create(key_type="aead", name="sym")
    assert hz.client.get(f"/api/v1/keys/{aead['id']}/public-key", headers=hz.h()).status_code == 400


def test_keystore_destroy_makes_ciphertext_unrecoverable(tmp_path):
    """Destroying a key removes its material; prior ciphertext can no longer be
    decrypted (the key is simply gone)."""
    hz = Harness(tmp_path)
    key = hz.create()
    ct = hz.post(f"/api/v1/keys/{key['id']}/encrypt", {"plaintext_b64": PT}).json()["ciphertext"]
    hz.ks.destroy_key(key["id"], force=True)
    with pytest.raises(KeyError):
        hz.ks.decrypt(key["id"], ct)
