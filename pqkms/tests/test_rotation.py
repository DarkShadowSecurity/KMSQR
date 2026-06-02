# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""Automatic key rotation policy: due detection, rotate_due, and the API setter."""
from datetime import datetime, timezone, timedelta

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
from app.api.auth import TokenAuth, SCOPES_ADMIN
from app.api.authz import Authorizer
from app.api.routes import build_router


def _ks(tmp_path):
    repo = make_repository(f"sqlite:///{(tmp_path / 'rot.db').as_posix()}")
    ks = KeyStore(repo, PassphraseCustodian("operator-passphrase-123456"))
    ks.initialize()
    return ks


def test_no_policy_means_never_due(tmp_path):
    ks = _ks(tmp_path)
    ks.create_key("k", "aead")
    assert ks.rotation_due() == []


def test_due_after_period_elapses(tmp_path):
    ks = _ks(tmp_path)
    mk = ks.create_key("k", "aead")
    ks.set_rotation_policy(mk.id, 30)
    # not due now
    assert ks.rotation_due() == []
    # due 31 days later
    future = datetime.now(timezone.utc) + timedelta(days=31)
    assert ks.rotation_due(now=future) == [mk.id]


def test_rotate_due_bumps_version_and_clears_due(tmp_path):
    ks = _ks(tmp_path)
    mk = ks.create_key("k", "aead")
    ks.set_rotation_policy(mk.id, 7)
    future = datetime.now(timezone.utc) + timedelta(days=8)
    rotated = ks.rotate_due(now=future)
    assert rotated == [mk.id]
    assert ks.get_key(mk.id).current_version == 2
    # the new version resets the clock: it is not due again at real-now (age ~0)
    assert ks.rotation_due() == []


def test_disabled_key_not_rotated(tmp_path):
    ks = _ks(tmp_path)
    mk = ks.create_key("k", "aead")
    ks.set_rotation_policy(mk.id, 1)
    ks.disable_key(mk.id)
    future = datetime.now(timezone.utc) + timedelta(days=5)
    assert ks.rotation_due(now=future) == []  # only enabled keys are candidates


def test_set_rotation_policy_validation(tmp_path):
    ks = _ks(tmp_path)
    mk = ks.create_key("k", "aead")
    with pytest.raises(ValueError):
        ks.set_rotation_policy(mk.id, 0)
    with pytest.raises(ValueError):
        ks.set_rotation_policy(mk.id, 10000)
    # clearing is allowed
    assert ks.set_rotation_policy(mk.id, None).rotation_period_days is None


def test_rotation_policy_via_api(tmp_path):
    ks = _ks(tmp_path)
    repo = ks.repo
    kp = HybridSigner.generate()
    audit = AuditLog(repo, (kp.private_key, kp.public_key, kp.suite))
    auth = TokenAuth(repo)
    _t, tok, _p = auth.create_token("admin", {SCOPES_ADMIN})
    limiter = Limiter(key_func=get_remote_address, default_limits=["100000/minute"])
    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(build_router(ks, audit, auth, Authorizer(repo), limiter))
    client = TestClient(app)
    h = {"Authorization": f"Bearer {tok}"}
    key = client.post("/api/v1/keys", json={"name": "k", "key_type": "aead"}, headers=h).json()
    r = client.post(f"/api/v1/keys/{key['id']}/rotation-policy", json={"period_days": 90}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["rotation_period_days"] == 90
    # clear it
    r2 = client.post(f"/api/v1/keys/{key['id']}/rotation-policy", json={"period_days": None}, headers=h)
    assert r2.status_code == 200 and r2.json()["rotation_period_days"] is None
