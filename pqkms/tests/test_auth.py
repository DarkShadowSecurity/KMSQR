# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""Auth / token unit tests."""
import pytest
from app.storage.repository import make_repository
from app.api.auth import TokenAuth, SCOPES_ADMIN, SCOPES_READ


@pytest.fixture
def auth(tmp_path):
    repo = make_repository(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    return TokenAuth(repo)


def test_token_roundtrip_verifies(auth):
    """The token returned to the caller must actually verify — guards against the
    create/verify hash-mismatch bug."""
    _tid, tok, _pid = auth.create_token("service-a", {SCOPES_ADMIN})
    scopes = auth.verify(tok)
    assert scopes == {SCOPES_ADMIN}


def test_token_scopes_preserved(auth):
    _tid, tok, _pid = auth.create_token("reader", {SCOPES_READ})
    assert auth.verify(tok) == {SCOPES_READ}


def test_invalid_token_rejected(auth):
    assert auth.verify("pqkms_deadbeef_notreal") is None
    assert auth.verify("bearer-style-nonsense") is None
    assert auth.verify("") is None


def test_revoked_token_rejected(auth):
    tid, tok, _pid = auth.create_token("temp", {SCOPES_READ})
    assert auth.verify(tok) is not None
    auth.revoke(tid)
    assert auth.verify(tok) is None


def test_has_any_token(auth):
    assert not auth.has_any_token()
    auth.create_token("first", {SCOPES_ADMIN})
    assert auth.has_any_token()


def test_unknown_scope_rejected(auth):
    with pytest.raises(ValueError):
        auth.create_token("bad", {"not-a-real-scope"})
