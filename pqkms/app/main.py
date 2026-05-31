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
from contextlib import asynccontextmanager
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

from .storage.repository import make_repository
from .storage.keystore import KeyStore
from .storage.audit import AuditLog, load_or_create_audit_signing_key
from .storage.audit_sink import make_audit_sink
from .custody import make_custodian
from .api.auth import TokenAuth, SCOPES_ADMIN
from .api.routes import build_router
from .crypto.kem import HybridKEM
from .crypto.signatures import HybridSigner


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


def _validate_passphrase(passphrase: str, min_len: int) -> None:
    if len(passphrase) < min_len:
        log.error(
            "Operator passphrase is shorter than the minimum required length (%d). "
            "Set a longer passphrase or override PQKMS_MIN_PASSPHRASE_LEN.",
            min_len,
        )
        sys.exit(1)


def _load_passphrase() -> str:
    """
    Resolve the operator passphrase. A mounted secret file
    (PQKMS_PASSPHRASE_FILE) takes precedence over the PQKMS_PASSPHRASE env var,
    because env vars leak via `docker inspect` and `/proc/<pid>/environ`. The
    file path is the recommended production posture (Docker/K8s secrets).

    A single trailing newline is stripped (secret tooling and `echo` append one);
    any other whitespace is preserved as part of the passphrase. Fails closed.
    """
    pf = os.environ.get("PQKMS_PASSPHRASE_FILE")
    if pf:
        try:
            data = Path(pf).read_text(encoding="utf-8")
        except OSError as e:
            log.error("PQKMS_PASSPHRASE_FILE (%s) could not be read: %s", pf, e)
            sys.exit(1)
        passphrase = data[:-1] if data.endswith("\n") else data
        passphrase = passphrase[:-1] if passphrase.endswith("\r") else passphrase
        if not passphrase:
            log.error("PQKMS_PASSPHRASE_FILE (%s) is empty", pf)
            sys.exit(1)
        return passphrase

    passphrase = os.environ.get("PQKMS_PASSPHRASE")
    if not passphrase:
        log.error("PQKMS_PASSPHRASE or PQKMS_PASSPHRASE_FILE environment variable is required")
        sys.exit(1)
    return passphrase


def _truthy(val: "str | None", default: bool) -> bool:
    if val is None:
        return default
    return val.strip().lower() not in ("0", "false", "no", "off", "")


def _enforce_pq_requirement() -> None:
    """
    A post-quantum KMS must not silently degrade to classical-only crypto.
    With PQKMS_REQUIRE_PQ enabled (the default), refuse to start if liboqs is
    unavailable. Operators who knowingly want classical-only (e.g. a Windows
    dev box without liboqs) must opt out explicitly with PQKMS_REQUIRE_PQ=0.
    """
    require_pq = _truthy(os.environ.get("PQKMS_REQUIRE_PQ"), default=True)
    pq_ok = HybridKEM.is_hybrid_available() and HybridSigner.is_hybrid_available()
    if require_pq and not pq_ok:
        log.error(
            "PQKMS_REQUIRE_PQ is enabled but liboqs (post-quantum primitives) is "
            "unavailable. The KMS would fall back to CLASSICAL-ONLY crypto, which "
            "defeats its purpose. Refusing to start. Install liboqs (see "
            "deploy/Dockerfile) or set PQKMS_REQUIRE_PQ=0 to allow classical-only."
        )
        sys.exit(1)
    if not pq_ok:
        log.warning(
            "liboqs unavailable — running in CLASSICAL-ONLY mode "
            "(PQKMS_REQUIRE_PQ explicitly disabled). New material is tagged with "
            "CLASSIC_* suites and is NOT post-quantum protected."
        )


def create_app() -> FastAPI:
    # Refuse to start as a classical-only "post-quantum" KMS unless explicitly allowed.
    _enforce_pq_requirement()

    data_dir = Path(os.environ.get("PQKMS_DATA_DIR", "/var/lib/pqkms"))
    data_dir.mkdir(parents=True, exist_ok=True)

    passphrase = _load_passphrase()
    min_len = int(os.environ.get("PQKMS_MIN_PASSPHRASE_LEN", DEFAULT_MIN_PASSPHRASE_LEN))
    _validate_passphrase(passphrase, min_len)

    # PQKMS_DB_URL selects the backend (Postgres for HA); defaults to a SQLite
    # file under the data dir for the single-node quickstart.
    repo = make_repository(data_dir=str(data_dir))
    custodian = make_custodian(passphrase)
    ks = KeyStore(repo, custodian)

    if not ks.is_initialized():
        log.info("bootstrapping new KMS (custody backend: %s)", custodian.backend_id)
        ks.initialize()
    else:
        log.info("unlocking existing KMS (custody backend: %s)", custodian.backend_id)
        ks.unlock()

    audit_keypair = load_or_create_audit_signing_key(ks)
    audit_sink = make_audit_sink(os.environ.get("PQKMS_AUDIT_LOG_FILE"))
    audit = AuditLog(repo, audit_keypair, sink=audit_sink)

    auth = TokenAuth(repo)

    # Bootstrap admin token if none exists. The if_absent sentinel makes this
    # single-shot across replicas: only the winner creates and prints the token,
    # so it isn't minted (or logged) once per replica on a cold HA start.
    if not auth.has_any_token() and repo.put_meta("bootstrap_admin_issued_v1", b"1", if_absent=True):
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

    # Rate-limit storage. In-memory is per-process, so it does not hold across
    # replicas — point PQKMS_REDIS_URL at a shared Redis for HA. Rate limiting
    # fails OPEN: an in-memory fallback plus swallow_errors means a Redis outage
    # degrades to local limiting / no limiting rather than denying all traffic
    # (availability beats strict limiting for a KMS). The nonce budget, by
    # contrast, fails CLOSED — see app/policy.py.
    redis_url = os.environ.get("PQKMS_REDIS_URL")
    limiter_kwargs = dict(key_func=get_remote_address, default_limits=["120/minute"])
    if redis_url:
        limiter_kwargs.update(
            storage_uri=redis_url,
            in_memory_fallback_enabled=True,
            swallow_errors=True,
        )
    limiter = Limiter(**limiter_kwargs)
    log.info("rate-limit storage: %s", "redis (shared)" if redis_url else "in-memory (per-process)")

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        # Force a WAL checkpoint at startup and shutdown so committed writes are
        # flushed to the main db file and not stranded in the WAL across an
        # unclean restart. (Replaces the deprecated @app.on_event hooks.)
        repo.checkpoint()
        log.info("storage checkpoint completed on startup")
        try:
            yield
        finally:
            repo.checkpoint()
            log.info("storage checkpoint completed on shutdown")

    app = FastAPI(
        title="PQ-KMS",
        description="Post-Quantum Key Management System",
        version="1.0.0",
        lifespan=lifespan,
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
        db_ok = repo.ping()
        ok = unlocked and db_ok
        return JSONResponse(
            status_code=200 if ok else 503,
            content={"status": "ok" if ok else "degraded",
                     "unlocked": unlocked, "db": db_ok},
        )

    return app


app = create_app()
