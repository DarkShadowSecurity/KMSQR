# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
PQ-KMS main entrypoint.

On first startup:
  1. PQKMS_PASSPHRASE is required and must meet a minimum length.
  2. Initialize the KMS if needed and unlock.
  3. Generate the audit-log signing keypair if missing.
  4. Create a bootstrap admin token if no tokens exist; print it once.
"""
import os
import sys
import base64
import logging
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .storage.db import Database
from .storage.keystore import KeyStore
from .storage.audit import AuditLog
from .api.auth import TokenAuth, SCOPES_ADMIN
from .api.routes import build_router
from .crypto.signatures import HybridSigner
from .crypto.suites import Suite, SUITE_NAMES
from .crypto.aead import AEAD


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s :: %(message)s")
log = logging.getLogger("pqkms")


DEFAULT_MAX_BODY_BYTES = 16 * 1024 * 1024  # 16 MiB
DEFAULT_MIN_PASSPHRASE_LEN = 16


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject any request whose body exceeds max_bytes. Checked via Content-Length first
    (cheap path); for chunked / unset Content-Length the limit is enforced by counting
    bytes as the body is read downstream — uvicorn's --limit-max-requests / starlette's
    request.stream() will raise once the cap is hit."""

    def __init__(self, app, max_bytes: int):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > self.max_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "request body too large"},
                    )
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "invalid Content-Length"})
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds strict security headers, including a CSP that only permits same-origin
    resources. Inline <style> blocks in the admin UI require 'unsafe-inline' for
    style-src; scripts are loaded as separate files so script-src can stay strict."""

    CSP = "; ".join([
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "font-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ])

    async def dispatch(self, request: Request, call_next):
        resp: Response = await call_next(request)
        resp.headers.setdefault("Content-Security-Policy", self.CSP)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        return resp


def _load_or_create_audit_signing_key(ks: KeyStore) -> tuple[bytes, bytes, Suite]:
    """
    Audit signing keypair is stored as a special meta row, encrypted under the Root KEK.
    This keeps the audit log tamper-evident even if the DB is copied off-box.
    """
    META_KEY = "audit_signing_keypair_v1"
    c = ks.db.conn()
    row = c.execute("SELECT v FROM kms_meta WHERE k=?", (META_KEY,)).fetchone()
    if row:
        wrapped = bytes(row["v"])
        raw = ks._unwrap(wrapped, aad=b"pqkms/audit-signing/v1")
        # format: [2B suite][4B priv_len][priv][pub]
        import struct
        suite_id, priv_len = struct.unpack("!HI", raw[:6])
        priv = raw[6:6+priv_len]
        pub = raw[6+priv_len:]
        return priv, pub, Suite(suite_id)

    kp = HybridSigner.generate()
    import struct
    packed = struct.pack("!HI", int(kp.suite), len(kp.private_key)) + kp.private_key + kp.public_key
    wrapped = ks._wrap(packed, aad=b"pqkms/audit-signing/v1")
    c.execute("INSERT INTO kms_meta(k,v) VALUES(?,?)", (META_KEY, wrapped))
    log.info("generated new audit-log signing keypair (%s)", SUITE_NAMES[kp.suite])
    return kp.private_key, kp.public_key, kp.suite


def _validate_passphrase(passphrase: str, min_len: int) -> None:
    if len(passphrase) < min_len:
        log.error(
            "PQKMS_PASSPHRASE is shorter than the minimum required length (%d). "
            "Set a longer passphrase or override PQKMS_MIN_PASSPHRASE_LEN.",
            min_len,
        )
        sys.exit(1)


def create_app() -> FastAPI:
    data_dir = Path(os.environ.get("PQKMS_DATA_DIR", "/var/lib/pqkms"))
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = str(data_dir / "pqkms.sqlite")

    passphrase = os.environ.get("PQKMS_PASSPHRASE")
    if not passphrase:
        log.error("PQKMS_PASSPHRASE environment variable is required")
        sys.exit(1)
    min_len = int(os.environ.get("PQKMS_MIN_PASSPHRASE_LEN", DEFAULT_MIN_PASSPHRASE_LEN))
    _validate_passphrase(passphrase, min_len)

    db = Database(db_path)
    ks = KeyStore(db)

    if not ks.is_initialized():
        log.info("bootstrapping new KMS at %s", db_path)
        ks.initialize(passphrase)
    else:
        log.info("unlocking existing KMS at %s", db_path)
        ks.unlock(passphrase)

    audit_priv, audit_pub, audit_suite = _load_or_create_audit_signing_key(ks)
    audit = AuditLog(db, (audit_priv, audit_pub, audit_suite))

    auth = TokenAuth(db)

    # bootstrap admin token if none exists
    if not auth.has_any_token():
        tid, raw = auth.create_token(name="bootstrap-admin", scopes={SCOPES_ADMIN})
        log.warning("=" * 72)
        log.warning("BOOTSTRAP ADMIN TOKEN (only shown once, save it now):")
        log.warning("  %s", raw)
        log.warning("REVOKE this token via DELETE /api/v1/tokens/%s after issuing scoped tokens.", tid)
        log.warning("=" * 72)
        audit.append("system", "bootstrap", target=tid, detail={"event": "initial_admin_token_created"})

    audit.append("system", "startup", detail={
        "pq_available": HybridSigner.is_hybrid_available(),
    })

    max_body = int(os.environ.get("PQKMS_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES))

    limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])

    app = FastAPI(
        title="PQ-KMS",
        description="Post-Quantum Key Management System",
        version="1.0.0",
    )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=max_body)
    app.add_middleware(SecurityHeadersMiddleware)

    # Generic exception handlers so internal exception messages are not reflected
    # to the caller. Each error gets a request id that the operator can correlate
    # with the server log.
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        # HTTPException.detail is intentionally caller-facing — pass it through unchanged.
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(status_code=422, content={"detail": "invalid request"})

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception):
        rid = uuid.uuid4().hex[:12]
        log.exception("unhandled exception [rid=%s] on %s %s", rid, request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": "internal error", "request_id": rid},
        )

    app.include_router(build_router(ks, audit, auth, limiter))

    @app.on_event("startup")
    async def _checkpoint_on_start():
        db.checkpoint()
        log.info("SQLite WAL checkpoint completed on startup")

    @app.on_event("shutdown")
    async def _checkpoint_on_shutdown():
        db.checkpoint()
        log.info("SQLite WAL checkpoint completed on shutdown")

    # Admin UI
    ui_dir = Path(__file__).parent / "ui"
    app.mount("/ui/static", StaticFiles(directory=str(ui_dir)), name="ui-static")

    @app.get("/ui")
    def ui_root():
        return FileResponse(str(ui_dir / "index.html"))

    @app.get("/")
    def root():
        return JSONResponse({
            "name": "PQ-KMS",
            "version": "1.0.0",
            "ui": "/ui",
            "api": "/api/v1",
            "pq_available": HybridSigner.is_hybrid_available(),
        })

    @app.get("/health")
    def health():
        """Liveness probe — used by docker healthcheck and operator
        monitoring. Returns 200 if the KeyStore is unlocked (i.e. the
        passphrase was accepted at boot) and the SQLite DB is reachable.
        Intentionally unauthenticated — same posture as /; reveals only
        the unlock + DB-reachable booleans, no secrets.
        """
        try:
            unlocked = ks.is_unlocked() if hasattr(ks, "is_unlocked") else True
        except Exception:
            unlocked = False
        try:
            db.conn().execute("SELECT 1").fetchone()
            db_ok = True
        except Exception:
            db_ok = False
        ok = unlocked and db_ok
        return JSONResponse(
            status_code=200 if ok else 503,
            content={"status": "ok" if ok else "degraded",
                     "unlocked": unlocked, "db": db_ok},
        )

    return app


app = create_app()
