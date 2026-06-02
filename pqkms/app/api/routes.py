# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""HTTP API routes for the KMS."""
import base64
import binascii
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter

from ..storage.keystore import KeyStore, KeyStateError
from ..storage.audit import AuditLog
from ..policy import NonceBudgetExceeded
from .auth import (
    TokenAuth,
    require_scope,
    SCOPES_ADMIN,
    SCOPES_ENCRYPT,
    SCOPES_DECRYPT,
    SCOPES_SIGN,
    SCOPES_VERIFY,
    SCOPES_READ,
    SCOPES_MANAGE,
)
from .authz import (
    Authorizer,
    parse_operations,
    OP_ENCRYPT,
    OP_DECRYPT,
    OP_SIGN,
    OP_VERIFY,
    OP_READ,
    OP_MANAGE,
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
    # Namespace (key-ring) name to create the key in. Defaults to "default".
    namespace: Optional[str] = Field(None, max_length=128)


class ImportKeyReq(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    # Base64 of exactly 32 bytes of AES-256 key material (BYOK).
    key_material_b64: str = Field(..., max_length=128)
    description: Optional[str] = Field(None, max_length=512)
    namespace: Optional[str] = Field(None, max_length=128)


class ScheduleDeletionReq(BaseModel):
    # Waiting period before the key becomes destroyable. Default 30 days; 7–30 is
    # the typical safety window. 0 is allowed for ephemeral/test keys.
    window_days: int = Field(30, ge=0, le=365)


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
    # Optional expiry. Omit for a non-expiring token. Cap at ~10 years.
    ttl_seconds: Optional[int] = Field(None, ge=1, le=10 * 365 * 24 * 3600)
    # Optionally bind the token to an existing principal (e.g. a second token for
    # a service that rotates credentials). Omit to create a fresh service
    # principal named after the token.
    principal_id: Optional[str] = Field(None, max_length=64)


class CreatePrincipalReq(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=128)
    ptype: str = Field("service", pattern=r"^(service|human)$")


class CreateNamespaceReq(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    description: Optional[str] = Field(None, max_length=512)


class CreateGrantReq(BaseModel):
    principal_id: str = Field(..., max_length=64)
    resource_type: str = Field(..., pattern=r"^(key|namespace)$")
    resource_id: str = Field(..., max_length=64)
    operations: list[str] = Field(..., min_length=1, max_length=8)


def _safe_call(action: str, fn, *args, **kwargs):
    """Run fn(*args, **kwargs); on failure, log the exception with full context and
    raise an HTTPException with a generic, caller-safe message. Internal exception
    text is never reflected to the client."""
    try:
        return fn(*args, **kwargs)
    except HTTPException:
        raise
    except KeyStateError as e:
        # The key exists but its lifecycle state forbids the operation.
        log.warning("%s refused: %s", action, e)
        raise HTTPException(409, f"key unavailable: {e}")
    except (ValueError, KeyError) as e:
        # ValueError / KeyError correspond to caller errors (bad key id, wrong type,
        # malformed input). It's safe to surface a 400 with a generic message; full
        # detail lands in the server log.
        log.warning("%s rejected: %s", action, e)
        raise HTTPException(400, "invalid request")
    except Exception:
        log.exception("%s failed unexpectedly", action)
        raise HTTPException(500, "internal error")


def _pagination(limit: int = 200, offset: int = 0) -> tuple[int, int]:
    """Shared list pagination. Bounded so a caller cannot request an unbounded
    scan. List endpoints keep returning a JSON array (ordered, newest first)."""
    if limit < 1 or limit > 1000:
        raise HTTPException(400, "limit out of range (1..1000)")
    if offset < 0:
        raise HTTPException(400, "offset must be >= 0")
    return limit, offset


def build_router(ks: KeyStore, audit: AuditLog, auth: TokenAuth, authz: Authorizer, limiter: Limiter) -> APIRouter:
    r = APIRouter(prefix="/api/v1")

    def _namespace_id_for(name: Optional[str]) -> str:
        ns = ks.repo.get_namespace_by_name(name or "default")
        if ns is None:
            raise HTTPException(400, "unknown namespace")
        return ns["id"]

    # ---- health / status ----
    @r.get("/status")
    @limiter.limit("60/minute")
    def status(request: Request, caller=Depends(require_scope(auth, SCOPES_READ))):
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
    def create_key(request: Request, req: CreateKeyReq, caller=Depends(require_scope(auth, SCOPES_MANAGE))):
        namespace_id = _namespace_id_for(req.namespace)
        authz.authorize_namespace_op(caller, OP_MANAGE, namespace_id)
        mk = _safe_call("key.create", ks.create_key, req.name, req.key_type, req.description, namespace_id)
        audit.append(caller.actor, "key.create", target=mk.id,
                     detail={"name": mk.name, "type": mk.key_type, "namespace_id": namespace_id})
        return mk

    @r.get("/keys")
    @limiter.limit("120/minute")
    def list_keys(request: Request, page: tuple = Depends(_pagination),
                  caller=Depends(require_scope(auth, SCOPES_READ))):
        return authz.filter_visible_keys(caller, ks.list_keys(limit=page[0], offset=page[1]))

    @r.get("/keys/{key_id}")
    @limiter.limit("120/minute")
    def get_key(request: Request, key_id: str, caller=Depends(require_scope(auth, SCOPES_READ))):
        # Authorize before fetching so an unauthorized caller can't distinguish a
        # forbidden key from a missing one (both 403 in strict mode).
        authz.authorize_key_op(caller, OP_READ, key_id)
        mk = ks.get_key(key_id)
        if not mk:
            raise HTTPException(404, "not found")
        return mk

    @r.post("/keys/{key_id}/rotate")
    @limiter.limit("10/minute")
    def rotate(request: Request, key_id: str, caller=Depends(require_scope(auth, SCOPES_MANAGE))):
        authz.authorize_key_op(caller, OP_MANAGE, key_id)
        try:
            mk = ks.rotate(key_id)
        except KeyError:
            raise HTTPException(404, "not found")
        except Exception:
            log.exception("key.rotate failed")  # request correlated via X-Request-ID
            raise HTTPException(500, "internal error")
        audit.append(caller.actor, "key.rotate", target=key_id, detail={"new_version": mk.current_version})
        return mk

    @r.post("/keys/import")
    @limiter.limit("30/minute")
    def import_key(request: Request, req: ImportKeyReq, caller=Depends(require_scope(auth, SCOPES_MANAGE))):
        namespace_id = _namespace_id_for(req.namespace)
        authz.authorize_namespace_op(caller, OP_MANAGE, namespace_id)
        material = _b64decode(req.key_material_b64)
        mk = _safe_call("key.import", ks.import_key, req.name, material, req.description, namespace_id)
        audit.append(caller.actor, "key.import", target=mk.id,
                     detail={"name": mk.name, "type": mk.key_type, "namespace_id": namespace_id, "origin": "imported"})
        return mk

    @r.get("/keys/{key_id}/public-key")
    @limiter.limit("120/minute")
    def public_key(request: Request, key_id: str, caller=Depends(require_scope(auth, SCOPES_READ))):
        authz.authorize_key_op(caller, OP_READ, key_id)
        return _safe_call("key.public_key", ks.export_public_key, key_id)

    @r.post("/keys/{key_id}/disable")
    @limiter.limit("30/minute")
    def disable_key(request: Request, key_id: str, caller=Depends(require_scope(auth, SCOPES_MANAGE))):
        authz.authorize_key_op(caller, OP_MANAGE, key_id)
        mk = _safe_call("key.disable", ks.disable_key, key_id)
        audit.append(caller.actor, "key.disable", target=key_id)
        return mk

    @r.post("/keys/{key_id}/enable")
    @limiter.limit("30/minute")
    def enable_key(request: Request, key_id: str, caller=Depends(require_scope(auth, SCOPES_MANAGE))):
        authz.authorize_key_op(caller, OP_MANAGE, key_id)
        mk = _safe_call("key.enable", ks.enable_key, key_id)
        audit.append(caller.actor, "key.enable", target=key_id)
        return mk

    @r.post("/keys/{key_id}/schedule-deletion")
    @limiter.limit("30/minute")
    def schedule_deletion(request: Request, key_id: str, req: ScheduleDeletionReq,
                          caller=Depends(require_scope(auth, SCOPES_MANAGE))):
        authz.authorize_key_op(caller, OP_MANAGE, key_id)
        mk = _safe_call("key.schedule_deletion", ks.schedule_deletion, key_id, req.window_days)
        audit.append(caller.actor, "key.schedule_deletion", target=key_id,
                     detail={"window_days": req.window_days, "deletion_at": mk.deletion_at})
        return mk

    @r.post("/keys/{key_id}/cancel-deletion")
    @limiter.limit("30/minute")
    def cancel_deletion(request: Request, key_id: str, caller=Depends(require_scope(auth, SCOPES_MANAGE))):
        authz.authorize_key_op(caller, OP_MANAGE, key_id)
        mk = _safe_call("key.cancel_deletion", ks.cancel_deletion, key_id)
        audit.append(caller.actor, "key.cancel_deletion", target=key_id)
        return mk

    @r.delete("/keys/{key_id}")
    @limiter.limit("10/minute")
    def destroy_key(request: Request, key_id: str, force: bool = False,
                    caller=Depends(require_scope(auth, SCOPES_MANAGE))):
        # force=true bypasses the deletion window and requires the admin scope —
        # an irreversible operation reserved for break-glass use.
        if force and not caller.is_admin:
            raise HTTPException(403, "force destruction requires the admin scope")
        authz.authorize_key_op(caller, OP_MANAGE, key_id)
        _safe_call("key.destroy", ks.destroy_key, key_id, force=force)
        audit.append(caller.actor, "key.destroy", target=key_id, detail={"force": force})
        return {"destroyed": True}

    # ---- AEAD encrypt/decrypt ----
    @r.post("/keys/{key_id}/encrypt")
    @limiter.limit("600/minute")
    def encrypt(request: Request, key_id: str, req: EncryptReq, caller=Depends(require_scope(auth, SCOPES_ENCRYPT))):
        authz.authorize_key_op(caller, OP_ENCRYPT, key_id)
        pt = _b64decode(req.plaintext_b64)
        aad = _b64decode_optional(req.aad_b64)
        try:
            out = ks.encrypt(key_id, pt, aad)
        except NonceBudgetExceeded as e:
            log.warning("key.encrypt refused: %s", e)
            raise HTTPException(409, "key nonce budget exhausted; rotate the key before encrypting more")
        except KeyStateError as e:
            log.warning("key.encrypt refused: %s", e)
            raise HTTPException(409, f"key unavailable: {e}")
        except (ValueError, KeyError) as e:
            log.warning("key.encrypt rejected: %s", e)
            raise HTTPException(400, "invalid request")
        except Exception:
            log.exception("key.encrypt failed unexpectedly")  # request correlated via X-Request-ID
            raise HTTPException(500, "internal error")
        audit.append(caller.actor, "key.encrypt", target=key_id, detail={"bytes": len(pt)})
        return out

    @r.post("/keys/{key_id}/decrypt")
    @limiter.limit("600/minute")
    def decrypt(request: Request, key_id: str, req: DecryptReq, caller=Depends(require_scope(auth, SCOPES_DECRYPT))):
        authz.authorize_key_op(caller, OP_DECRYPT, key_id)
        aad = _b64decode_optional(req.aad_b64)
        try:
            pt = ks.decrypt(key_id, req.ciphertext_b64, aad)
        except KeyStateError as e:
            log.warning("key.decrypt refused: %s", e)
            raise HTTPException(409, f"key unavailable: {e}")
        except (ValueError, KeyError) as e:
            log.warning("key.decrypt rejected: %s", e)
            raise HTTPException(400, "decrypt failed")
        except Exception:
            log.exception("key.decrypt failed unexpectedly")  # request correlated via X-Request-ID
            raise HTTPException(500, "internal error")
        audit.append(caller.actor, "key.decrypt", target=key_id, detail={"bytes": len(pt)})
        return {"plaintext_b64": base64.b64encode(pt).decode()}

    # ---- sign / verify ----
    @r.post("/keys/{key_id}/sign")
    @limiter.limit("600/minute")
    def sign(request: Request, key_id: str, req: SignReq, caller=Depends(require_scope(auth, SCOPES_SIGN))):
        authz.authorize_key_op(caller, OP_SIGN, key_id)
        out = _safe_call("key.sign", ks.sign, key_id, _b64decode(req.message_b64))
        audit.append(caller.actor, "key.sign", target=key_id)
        return out

    @r.post("/keys/{key_id}/verify")
    @limiter.limit("600/minute")
    def verify(request: Request, key_id: str, req: VerifyReq, caller=Depends(require_scope(auth, SCOPES_VERIFY))):
        authz.authorize_key_op(caller, OP_VERIFY, key_id)
        ok = _safe_call("key.verify", ks.verify, key_id, _b64decode(req.message_b64), req.signature_b64, req.version)
        return {"valid": ok}

    # ---- KEM wrap / unwrap ----
    @r.post("/keys/{key_id}/wrap")
    @limiter.limit("600/minute")
    def wrap(request: Request, key_id: str, req: WrapReq, caller=Depends(require_scope(auth, SCOPES_ENCRYPT))):
        authz.authorize_key_op(caller, OP_ENCRYPT, key_id)
        out = _safe_call("key.wrap", ks.wrap_data_key, key_id, _b64decode(req.data_key_b64))
        audit.append(caller.actor, "key.wrap", target=key_id)
        return out

    @r.post("/keys/{key_id}/unwrap")
    @limiter.limit("600/minute")
    def unwrap(request: Request, key_id: str, req: UnwrapReq, caller=Depends(require_scope(auth, SCOPES_DECRYPT))):
        authz.authorize_key_op(caller, OP_DECRYPT, key_id)
        try:
            dk = ks.unwrap_data_key(key_id, req.encapsulation_b64, req.wrapped_key_b64, req.version)
        except KeyStateError as e:
            log.warning("key.unwrap refused: %s", e)
            raise HTTPException(409, f"key unavailable: {e}")
        except (ValueError, KeyError) as e:
            log.warning("key.unwrap rejected: %s", e)
            raise HTTPException(400, "unwrap failed")
        except Exception:
            log.exception("key.unwrap failed unexpectedly")  # request correlated via X-Request-ID
            raise HTTPException(500, "internal error")
        audit.append(caller.actor, "key.unwrap", target=key_id)
        return {"data_key_b64": base64.b64encode(dk).decode()}

    # ---- audit ----
    @r.get("/audit")
    @limiter.limit("60/minute")
    def audit_list(request: Request, limit: int = 200, caller=Depends(require_scope(auth, SCOPES_READ))):
        if limit < 1 or limit > 1000:
            raise HTTPException(400, "limit out of range")
        return {"entries": audit.list(limit=limit)}

    @r.get("/audit/verify")
    @limiter.limit("10/minute")
    def audit_verify(request: Request, caller=Depends(require_scope(auth, SCOPES_ADMIN))):
        ok, bad = audit.verify_chain()
        return {"valid": ok, "first_bad_seq": bad}

    # ---- namespaces ----
    @r.post("/namespaces")
    @limiter.limit("10/minute")
    def create_namespace(request: Request, req: CreateNamespaceReq, caller=Depends(require_scope(auth, SCOPES_ADMIN))):
        import uuid as _uuid
        from datetime import datetime as _dt, timezone as _tz
        if ks.repo.get_namespace_by_name(req.name) is not None:
            raise HTTPException(409, "namespace already exists")
        nid = str(_uuid.uuid4())
        ks.repo.insert_namespace({
            "id": nid, "name": req.name,
            "created_at": _dt.now(_tz.utc).isoformat(), "description": req.description,
        })
        audit.append(caller.actor, "namespace.create", target=nid, detail={"name": req.name})
        return {"id": nid, "name": req.name, "description": req.description}

    @r.get("/namespaces")
    @limiter.limit("60/minute")
    def list_namespaces(request: Request, caller=Depends(require_scope(auth, SCOPES_READ))):
        return ks.repo.list_namespaces()  # bounded set; pagination not needed

    # ---- grants ----
    @r.post("/grants")
    @limiter.limit("30/minute")
    def create_grant(request: Request, req: CreateGrantReq, caller=Depends(require_scope(auth, SCOPES_ADMIN))):
        import uuid as _uuid
        from datetime import datetime as _dt, timezone as _tz
        try:
            ops = parse_operations(req.operations)
        except ValueError as e:
            log.warning("grant.create rejected: %s", e)
            raise HTTPException(400, "invalid operations")
        # Validate the principal and resource exist, so grants never dangle.
        if auth.get_principal(req.principal_id) is None:
            raise HTTPException(400, "unknown principal")
        if req.resource_type == "namespace":
            if ks.repo.get_namespace_by_id(req.resource_id) is None:
                raise HTTPException(400, "unknown namespace")
        elif ks.repo.get_key_namespace(req.resource_id) is None:
            raise HTTPException(400, "unknown key")
        gid = str(_uuid.uuid4())
        authoritative = ks.repo.upsert_grant({
            "id": gid, "principal_id": req.principal_id, "resource_type": req.resource_type,
            "resource_id": req.resource_id, "operations": ",".join(sorted(ops)),
            "created_at": _dt.now(_tz.utc).isoformat(), "created_by": caller.principal_id,
        })
        audit.append(caller.actor, "grant.create", target=authoritative, detail={
            "principal_id": req.principal_id, "resource_type": req.resource_type,
            "resource_id": req.resource_id, "operations": sorted(ops),
        })
        return {"id": authoritative, "principal_id": req.principal_id, "resource_type": req.resource_type,
                "resource_id": req.resource_id, "operations": sorted(ops)}

    @r.get("/grants")
    @limiter.limit("60/minute")
    def list_grants(request: Request, principal_id: Optional[str] = None, page: tuple = Depends(_pagination),
                    caller=Depends(require_scope(auth, SCOPES_ADMIN))):
        rows = (ks.repo.get_grants_for_principal(principal_id) if principal_id
                else ks.repo.list_grants(limit=page[0], offset=page[1]))
        return [{**g, "operations": sorted(o for o in g["operations"].split(",") if o)} for g in rows]

    @r.delete("/grants/{grant_id}")
    @limiter.limit("60/minute")
    def delete_grant(request: Request, grant_id: str, caller=Depends(require_scope(auth, SCOPES_ADMIN))):
        if not ks.repo.delete_grant(grant_id):
            raise HTTPException(404, "not found")
        audit.append(caller.actor, "grant.delete", target=grant_id)
        return {"deleted": True}

    # ---- principals ----
    @r.post("/principals")
    @limiter.limit("10/minute")
    def create_principal(request: Request, req: CreatePrincipalReq, caller=Depends(require_scope(auth, SCOPES_ADMIN))):
        try:
            pid = auth.create_principal(req.display_name, req.ptype)
        except ValueError as e:
            log.warning("principal.create rejected: %s", e)
            raise HTTPException(400, "invalid principal")
        audit.append(caller.actor, "principal.create", target=pid,
                     detail={"display_name": req.display_name, "ptype": req.ptype})
        return {"id": pid, "display_name": req.display_name, "ptype": req.ptype}

    @r.get("/principals")
    @limiter.limit("60/minute")
    def list_principals(request: Request, page: tuple = Depends(_pagination),
                        caller=Depends(require_scope(auth, SCOPES_ADMIN))):
        return auth.list_principals(limit=page[0], offset=page[1])

    @r.delete("/principals/{principal_id}")
    @limiter.limit("60/minute")
    def delete_principal(request: Request, principal_id: str, caller=Depends(require_scope(auth, SCOPES_ADMIN))):
        if not auth.delete_principal(principal_id):
            raise HTTPException(404, "not found")
        audit.append(caller.actor, "principal.delete", target=principal_id)
        return {"deleted": True}

    # ---- tokens ----
    @r.post("/tokens")
    @limiter.limit("10/minute")
    def create_token(request: Request, req: CreateTokenReq, caller=Depends(require_scope(auth, SCOPES_ADMIN))):
        try:
            tid, raw, pid = auth.create_token(req.name, set(req.scopes), req.ttl_seconds, req.principal_id)
        except ValueError as e:
            log.warning("token.create rejected: %s", e)
            raise HTTPException(400, "invalid scope or principal")
        audit.append(
            caller.actor, "token.create", target=tid,
            detail={"scopes": req.scopes, "name": req.name, "ttl_seconds": req.ttl_seconds, "principal_id": pid},
        )
        return {
            "id": tid, "token": raw, "principal_id": pid,
            "warning": "this token is only shown once; store it securely",
        }

    @r.get("/tokens")
    @limiter.limit("60/minute")
    def list_tokens(request: Request, page: tuple = Depends(_pagination),
                    caller=Depends(require_scope(auth, SCOPES_ADMIN))):
        return auth.list_tokens(limit=page[0], offset=page[1])

    @r.delete("/tokens/{token_id}")
    @limiter.limit("60/minute")
    def revoke_token(request: Request, token_id: str, caller=Depends(require_scope(auth, SCOPES_ADMIN))):
        auth.revoke(token_id)
        audit.append(caller.actor, "token.revoke", target=token_id)
        return {"revoked": True}

    return r
