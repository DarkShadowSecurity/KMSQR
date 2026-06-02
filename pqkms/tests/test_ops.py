# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Ops & observability: list pagination, liveness/readiness probes, the CEF audit
sink option, and the optional-tracing no-op path.
"""
import base64
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.storage.repository import make_repository
from app.storage.keystore import KeyStore
from app.storage.audit import AuditLog
from app.storage.audit_sink import make_audit_sink, entry_to_cef, NullAuditSink
from app.custody import PassphraseCustodian
from app.crypto.signatures import HybridSigner
from app.api.auth import TokenAuth, SCOPES_ADMIN
from app.api.authz import Authorizer
from app.api.routes import build_router
from app.obs.tracing import setup_tracing


def _client(tmp_path):
    repo = make_repository(f"sqlite:///{(tmp_path / 'ops.db').as_posix()}")
    ks = KeyStore(repo, PassphraseCustodian("operator-passphrase-123456"))
    ks.initialize()
    kp = HybridSigner.generate()
    audit = AuditLog(repo, (kp.private_key, kp.public_key, kp.suite))
    auth = TokenAuth(repo)
    _t, tok, _p = auth.create_token("admin", {SCOPES_ADMIN})
    limiter = Limiter(key_func=get_remote_address, default_limits=["100000/minute"])
    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(build_router(ks, audit, auth, Authorizer(repo), limiter))
    return TestClient(app), tok


# ----------------------------------------------------------- pagination -------

def test_list_keys_pagination(tmp_path):
    client, tok = _client(tmp_path)
    h = {"Authorization": f"Bearer {tok}"}
    for i in range(5):
        assert client.post("/api/v1/keys", json={"name": f"k{i}", "key_type": "aead"}, headers=h).status_code == 200
    # default returns all 5 (still a JSON array)
    allk = client.get("/api/v1/keys", headers=h).json()
    assert isinstance(allk, list) and len(allk) == 5
    # limit + offset slice it
    first2 = client.get("/api/v1/keys?limit=2&offset=0", headers=h).json()
    next2 = client.get("/api/v1/keys?limit=2&offset=2", headers=h).json()
    assert len(first2) == 2 and len(next2) == 2
    assert {k["id"] for k in first2}.isdisjoint({k["id"] for k in next2})


def test_pagination_bounds(tmp_path):
    client, tok = _client(tmp_path)
    h = {"Authorization": f"Bearer {tok}"}
    assert client.get("/api/v1/keys?limit=0", headers=h).status_code == 400
    assert client.get("/api/v1/keys?limit=1001", headers=h).status_code == 400
    assert client.get("/api/v1/keys?offset=-1", headers=h).status_code == 400


# -------------------------------------------------------- liveness/ready ------

def test_liveness_and_readiness(tmp_path, monkeypatch):
    monkeypatch.setenv("PQKMS_REQUIRE_PQ", "0")
    monkeypatch.setenv("PQKMS_PASSPHRASE", "a-very-strong-operator-passphrase")
    monkeypatch.setenv("PQKMS_DATA_DIR", str(tmp_path))
    from app.main import create_app
    client = TestClient(create_app())
    assert client.get("/livez").status_code == 200
    assert client.get("/livez").json()["status"] == "alive"
    ready = client.get("/readyz")
    assert ready.status_code == 200 and ready.json()["unlocked"] is True
    # /health remains a readiness alias
    assert client.get("/health").status_code == 200


# --------------------------------------------------------------- CEF sink -----

def test_entry_to_cef_format_and_escaping():
    line = entry_to_cef({
        "seq": 7, "ts": "2026-06-02T00:00:00Z", "actor": "principal:abc",
        "action": "key.create", "target": "key=123", "detail": '{"a":1}',
    })
    assert line.startswith("CEF:0|DarkShadowSec|PQ-KMS|1.0|key.create|key.create|3|")
    assert "act=key.create" in line
    assert "suser=principal:abc" in line
    # '=' in a value is escaped so the SIEM parser doesn't split the field
    assert "cs1=key\\=123" in line


def test_make_audit_sink_cef_writes_cef_lines(tmp_path):
    p = tmp_path / "audit.cef"
    sink = make_audit_sink(str(p), "cef")
    sink.emit({"seq": 1, "ts": "t", "actor": "a", "action": "x", "target": None,
               "detail": "{}", "prev_hash": b"\x00", "entry_hash": b"\x01", "signature": b"\x02"})
    assert p.read_text(encoding="utf-8").startswith("CEF:0|DarkShadowSec|PQ-KMS|1.0|x|")


def test_make_audit_sink_json_default(tmp_path):
    p = tmp_path / "audit.jsonl"
    sink = make_audit_sink(str(p), "json")
    sink.emit({"seq": 1, "ts": "t", "actor": "a", "action": "x", "target": None,
               "detail": "{}", "prev_hash": b"\x00", "entry_hash": b"\x01", "signature": b"\x02"})
    row = json.loads(p.read_text(encoding="utf-8").strip())
    assert row["action"] == "x" and row["entry_hash_b64"] == base64.b64encode(b"\x01").decode()


def test_make_audit_sink_rejects_unknown_format():
    with pytest.raises(RuntimeError):
        make_audit_sink("x.log", "xml")


def test_make_audit_sink_none_is_null():
    assert isinstance(make_audit_sink(None), NullAuditSink)


# ----------------------------------------------------------- tracing no-op ----

def test_setup_tracing_disabled_by_default(monkeypatch):
    monkeypatch.delenv("PQKMS_OTEL_ENABLED", raising=False)
    app = FastAPI()
    assert setup_tracing(app) is False  # disabled -> no-op, never raises
