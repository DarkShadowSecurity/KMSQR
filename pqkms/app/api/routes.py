# Copyright (c) 2026 DarkShadowSec LLC. All Rights Reserved.
# Proprietary and confidential. See LICENSE for terms.
"""HTTP API routes for the KMS."""
import base64
import binascii
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter

from ..storage.keystore import KeyStore
from ..storage.audit import AuditLog
from .auth import (
    TokenAuth,
    require_scope,
    SCOPES_ADMIN,
    SCOPES_ENCRYPT,
    SCOPES_DECRYPT,
    SCOPES_SIGN,
    SCOPES_VERIFY,
    SCOPES_READ,
)


log = logging.getLogger("pqkms.api")


def _b64decode(s: str) -> bytes:
    """Strict base64 decode that surfaces a 400, never a stack trace."""
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(400, "invalid base64 input")


def _b64decode_optional(s: Optional[str]) -> bytes:
    return _b64decode(s) if s else b""


class CreateKeyReq(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    key_type: str = Field(..., pattern=r"^(aead|kem|sig)$")
    description: Optional[str] = Field(None, max_length=512)


class EncryptReq(BaseModel):
    plaintext_b64: str = Field(..., max_length=32_000_000)  # ~24 MiB plaintext cap
    aad_b64: Optional[str] = Field(None, max_length=8192)


class DecryptReq(BaseModel):
    ciphertext_b64: str = Field(..., max_length=32_000_000)
    aad_b64: Optional[str] = Field(None, max_length=8192)


class SignReq(BaseModel):
    message_b64: str = Field(..., max_length=32_000_000)


class VerifyReq(BaseModel):
    message_b64: str = Field(..., max_length=32_000_000)
    signature_b64: str = Field(..., max_length=65536)
    version: Optional[int] = Field(None, ge=1, le=2**31 - 1)


class WrapReq(BaseModel):
    data_key_b64: str = Field(..., max_length=2048)


class UnwrapReq(BaseModel):
    encapsulation_b64: str = Field(..., max_length=8192)
    wrapped_key_b64: str = Field(..., max_length=8192)
    version: Optional[int] = Field(None, ge=1, le=2**31 - 1)


class CreateTokenReq(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    scopes: list[str] = Field(..., min_length=1, max_length=16)


def _safe_call(action: str, fn, *args, **kwargs):
    """Run fn(*args, **kwargs); on failure, log the exception with full context and
    raise an HTTPException with a generic, caller-safe message. Internal exception
    text is never reflected to the client."""
    try:
        return fn(*args, **kwargs)
    except HTTPException:
        raise
    except (ValueError, KeyError) as e:
        # ValueError / KeyError correspond to caller errors (bad key id, wrong type,
        # malformed input). It's safe to surface a 400 with a generic message; full
        # detail lands in the server log.
        log.warning("%s rejected: %s", action, e)
        raise HTTPException(400, "invalid request")
    except Exception:
        log.exception("%s failed unexpectedly", action)
        raise HTTPException(500, "internal error")


def build_router(ks: KeyStore, audit: AuditLog, auth: TokenAuth, limiter: Limiter) -> APIRouter:
    r = APIRouter(prefix="/api/v1")

    def _actor(scopes: set[str]) -> str:
        return f"token[{','.join(sorted(scopes))}]"

    # ---- health / status ----
    @r.get("/status")
    @limiter.limit("60/minute")
    def status(request: Request, scopes=Depends(require_scope(auth, SCOPES_READ))):
        from ..crypto.kem import HybridKEM
        from ..crypto.signatures import HybridSigner
        return {
            "initialized": ks.is_initialized(),
            "unlocked": ks.is_unlocked(),
            "pq_available": HybridKEM.is_hybrid_available() and HybridSigner.is_hybrid_available(),
        }

    # ---- key lifecycle ----
    @r.post("/keys")
    @limiter.limit("30/minute")
    def create_key(request: Request, req: CreateKeyReq, scopes=Depends(require_scope(auth, SCOPES_ADMIN))):
        mk = _safe_call("key.create", ks.create_key, req.name, req.key_type, req.description)
        audit.append(_actor(scopes), "key.create", target=mk.id, detail={"name": mk.name, "type": mk.key_type})
        return mk

    @r.get("/keys")
    @limiter.limit("120/minute")
    def list_keys(request: Request, scopes=Depends(require_scope(auth, SCOPES_READ))):
        return ks.list_keys()

    @r.get("/keys/{key_id}")
    @limiter.limit("120/minute")
    def get_key(request: Request, key_id: str, scopes=Depends(require_scope(auth, SCOPES_READ))):
        mk = ks.get_key(key_id)
        if not mk:
            raise HTTPException(404, "not found")
        return mk

    @r.post("/keys/{key_id}/rotate")
    @limiter.limit("10/minute")
    def rotate(request: Request, key_id: str, scopes=Depends(require_scope(auth, SCOPES_ADMIN))):
        try:
            mk = ks.rotate(key_id)
        except KeyError:
            raise HTTPException(404, "not found")
        except Exception:
            log.exception("key.rotate failed for %s", key_id)
            raise HTTPException(500, "internal error")
        audit.append(_actor(scopes), "key.rotate", target=key_id, detail={"new_version": mk.current_version})
        return mk

    # ---- AEAD encrypt/decrypt ----
    @r.post("/keys/{key_id}/encrypt")
    @limiter.limit("600/minute")
    def encrypt(request: Request, key_id: str, req: EncryptReq, scopes=Depends(require_scope(auth, SCOPES_ENCRYPT))):
        pt = _b64decode(req.plaintext_b64)
        aad = _b64decode_optional(req.aad_b64)
        out = _safe_call("key.encrypt", ks.encrypt, key_id, pt, aad)
        audit.append(_actor(scopes), "key.encrypt", target=key_id, detail={"bytes": len(pt)})
        return out

    @r.post("/keys/{key_id}/decrypt")
    @limiter.limit("600/minute")
    def decrypt(request: Request, key_id: str, req: DecryptReq, scopes=Depends(require_scope(auth, SCOPES_DECRYPT))):
        aad = _b64decode_optional(req.aad_b64)
        try:
            pt = ks.decrypt(key_id, req.ciphertext_b64, aad)
        except (ValueError, KeyError) as e:
            log.warning("key.decrypt rejected: %s", e)
            raise HTTPException(400, "decrypt failed")
        except Exception:
            log.exception("key.decrypt failed unexpectedly for %s", key_id)
            raise HTTPException(500, "internal error")
        audit.append(_actor(scopes), "key.decrypt", target=key_id, detail={"bytes": len(pt)})
        return {"plaintext_b64": base64.b64encode(pt).decode()}

    # ---- sign / verify ----
    @r.post("/keys/{key_id}/sign")
    @limiter.limit("600/minute")
    def sign(request: Request, key_id: str, req: SignReq, scopes=Depends(require_scope(auth, SCOPES_SIGN))):
        out = _safe_call("key.sign", ks.sign, key_id, _b64decode(req.message_b64))
        audit.append(_actor(scopes), "key.sign", target=key_id)
        return out

    @r.post("/keys/{key_id}/verify")
    @limiter.limit("600/minute")
    def verify(request: Request, key_id: str, req: VerifyReq, scopes=Depends(require_scope(auth, SCOPES_VERIFY))):
        ok = _safe_call("key.verify", ks.verify, key_id, _b64decode(req.message_b64), req.signature_b64, req.version)
        return {"valid": ok}

    # ---- KEM wrap / unwrap ----
    @r.post("/keys/{key_id}/wrap")
    @limiter.limit("600/minute")
    def wrap(request: Request, key_id: str, req: WrapReq, scopes=Depends(require_scope(auth, SCOPES_ENCRYPT))):
        out = _safe_call("key.wrap", ks.wrap_data_key, key_id, _b64decode(req.data_key_b64))
        audit.append(_actor(scopes), "key.wrap", target=key_id)
        return out

    @r.post("/keys/{key_id}/unwrap")
    @limiter.limit("600/minute")
    def unwrap(request: Request, key_id: str, req: UnwrapReq, scopes=Depends(require_scope(auth, SCOPES_DECRYPT))):
        try:
            dk = ks.unwrap_data_key(key_id, req.encapsulation_b64, req.wrapped_key_b64, req.version)
        except (ValueError, KeyError) as e:
            log.warning("key.unwrap rejected: %s", e)
            raise HTTPException(400, "unwrap failed")
        except Exception:
            log.exception("key.unwrap failed unexpectedly for %s", key_id)
            raise HTTPException(500, "internal error")
        audit.append(_actor(scopes), "key.unwrap", target=key_id)
        return {"data_key_b64": base64.b64encode(dk).decode()}

    # ---- audit ----
    @r.get("/audit")
    @limiter.limit("60/minute")
    def audit_list(request: Request, limit: int = 200, scopes=Depends(require_scope(auth, SCOPES_READ))):
        if limit < 1 or limit > 1000:
            raise HTTPException(400, "limit out of range")
        return {"entries": audit.list(limit=limit)}

    @r.get("/audit/verify")
    @limiter.limit("10/minute")
    def audit_verify(request: Request, scopes=Depends(require_scope(auth, SCOPES_ADMIN))):
        ok, bad = audit.verify_chain()
        return {"valid": ok, "first_bad_seq": bad}

    # ---- tokens ----
    @r.post("/tokens")
    @limiter.limit("10/minute")
    def create_token(request: Request, req: CreateTokenReq, scopes=Depends(require_scope(auth, SCOPES_ADMIN))):
        try:
            tid, raw = auth.create_token(req.name, set(req.scopes))
        except ValueError as e:
            log.warning("token.create rejected: %s", e)
            raise HTTPException(400, "invalid scope")
        audit.append(_actor(scopes), "token.create", target=tid, detail={"scopes": req.scopes, "name": req.name})
        return {"id": tid, "token": raw, "warning": "this token is only shown once; store it securely"}

    @r.get("/tokens")
    @limiter.limit("60/minute")
    def list_tokens(request: Request, scopes=Depends(require_scope(auth, SCOPES_ADMIN))):
        return auth.list_tokens()

    @r.delete("/tokens/{token_id}")
    @limiter.limit("60/minute")
    def revoke_token(request: Request, token_id: str, scopes=Depends(require_scope(auth, SCOPES_ADMIN))):
        auth.revoke(token_id)
        audit.append(_actor(scopes), "token.revoke", target=token_id)
        return {"revoked": True}

    return r
