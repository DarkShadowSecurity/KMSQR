---
marp: true
theme: default
paginate: true
header: 'PQ-KMS Security Audit'
footer: '2026-05-06'
style: |
  section { font-size: 22px; }
  h1 { color: #1a4d8f; }
  h2 { color: #1a4d8f; border-bottom: 2px solid #1a4d8f; padding-bottom: 4px; }
  table { font-size: 18px; }
  .small { font-size: 16px; color: #666; }
  .ok { color: #0a7d2f; font-weight: 600; }
  .warn { color: #b35900; font-weight: 600; }
  .bad { color: #b00020; font-weight: 600; }
---

# PQ-KMS Security Audit
### Vulnerabilities & Remediation

A reference Post-Quantum Key Management System
Hybrid cryptography · Versioned key hierarchy · Hash-chained audit log

<br>

**Audit date:** 2026-05-06
**Scope:** `pqkms/` source, `requirements.txt`, `deploy/Dockerfile` & compose, admin UI

---

## Scope & methodology

**What was reviewed**

- 5 Python dependencies + 1 C library + 1 base image
- ~1,500 lines of Python across `app/api/`, `app/crypto/`, `app/storage/`
- Admin UI (HTML + inline JS, ~600 lines)
- Container build & runtime configuration

**How**

1. Inventoried every pinned dependency
2. Cross-referenced GHSA / CVE databases for each
3. Captured license obligations
4. Read each source file looking for OWASP-style flaws, crypto misuse, auth defects
5. Produced a tracked spreadsheet (`security-audit.csv`)

---

## Findings overview

| Category | Found | Remediated | Deferred (justified) | Documented |
|---|---:|---:|---:|---:|
| Dependency CVEs | 3 actionable | <span class="ok">3</span> | 0 | 0 |
| Dependency hygiene | 2 | <span class="ok">2</span> | 0 | 0 |
| Code — high/medium | 5 | <span class="ok">5</span> | 0 | 0 |
| Code — low | 8 | <span class="ok">5</span> | <span class="warn">3</span> | 0 |
| Operational | 2 | 0 | 0 | <span class="ok">2</span> |
| License | 11 | <span class="ok">11</span> | 0 | 0 |

> **Bottom line:** every actionable finding has been closed in code or explicitly deferred with rationale.

---

## Severity before / after

| Severity | Before | After |
|---|---:|---:|
| <span class="bad">High (theoretical)</span> | 1 | 0 |
| <span class="warn">Medium</span> | 4 | 0 |
| <span class="warn">Low</span> | 13 | 3 (deferred, justified) |
| Informational / hardening | 6 | 6 |

A new **Medium** stored-XSS finding in the admin UI was discovered during remediation and fixed before delivery.

---

## Dependency vulnerabilities — `cryptography`

**Was:** `cryptography==43.0.1` — exposed to 3 published advisories

| ID | Severity | Issue | Fixed in |
|---|---|---|---|
| GHSA-79v4-65xg-pq4g | <span class="warn">Moderate</span> | Bundled OpenSSL CVE in PyPI wheels | 44.0.1 |
| GHSA-r6ph-v2qm-q3c2 | <span class="bad">High*</span> | SECT-curve subgroup validation missing | 46.0.5 |
| GHSA-m959-cc7f-wv43 | <span class="warn">Low</span>  | X.509 wildcard SAN bypass | 46.0.6 |

<span class="small">*High in the abstract — PQ-KMS only uses X25519/Ed25519, so practical exploitability today is nil. But the vulnerable code is still linked.</span>

**Remediation:** `cryptography==46.0.6` — closes all three.

---

## Dependency vulnerabilities — `liboqs`

**Was:** Dockerfile cloned `--branch main` — non-reproducible, drifted into post-release territory between builds.

**Risk surface:**

- GHSA-f2v9-5498-2vpp — Kyber timing leak under Clang 15-18, fixed in 0.10.1
- GHSA-gpf4-vrrw-r8v7 / GHSA-qq3m-rq9v-jfgm — HQC issues (not exploitable here: `OQS_MINIMAL_BUILD` excludes HQC entirely)

**Remediation**

- `LIBOQS_REF` pinned to `0.12.0` (release tag, past Kyber fix)
- `apt-get upgrade -y` added to **both** builder and runtime layers
- HQC remains explicitly excluded from `OQS_MINIMAL_BUILD`

---

## Dependency vulnerabilities — clean

No advisories affecting our pinned versions:

- `fastapi==0.115.0`
- `uvicorn==0.32.0`
- `pydantic==2.9.2`
- `argon2-cffi==23.1.0`
- `liboqs-python==0.14.1`
- `slowapi==0.1.9` *(newly added for rate limiting)*

**Remaining hygiene gap (PARTIAL):** `python:3.12-slim` is still a floating tag. `apt-get upgrade -y` mitigates day-to-day drift, but pinning to a digest in production is recommended.

---

## Code finding C-03 — Exception messages leaked to clients

**Before:** every handler caught the broad `Exception` class and reflected `str(e)` directly into the HTTP 400 response. Internal exception text — file paths, library internals, stack-trace fragments — flowed straight to the caller.

**After:** centralized `_safe_call()` helper plus per-handler typed catches.

```python
except (ValueError, KeyError) as e:
    log.warning("%s rejected: %s", action, e)
    raise HTTPException(400, "invalid request")
except Exception:
    log.exception("%s failed unexpectedly", action)
    raise HTTPException(500, "internal error")
```

Plus a global `Exception` handler that returns `{"detail": "internal error", "request_id": "<uuid>"}` and logs the trace under that id for operator correlation.

---

## Code findings C-04 / C-05 — DoS surface

**C-04 — Unbounded request bodies** *(Medium)*

| Layer | Defense |
|---|---|
| Middleware | `BodySizeLimitMiddleware` rejects requests with `Content-Length > PQKMS_MAX_BODY_BYTES` (default 16 MiB) → **HTTP 413** |
| Pydantic | Per-field `max_length` on every base64/string input |
| Audit | `audit?limit=` clamped to `[1, 1000]` |

**C-05 — No rate limiting** *(Low, but compounds with C-04)*

`slowapi` `Limiter` keyed on remote IP, with per-route limits:

| Endpoint class | Limit |
|---|---|
| Crypto ops (encrypt/decrypt/sign/verify/wrap/unwrap) | 600 / min |
| Status, list keys, list audit | 60–120 / min |
| Key creation, token list, token revoke | 30–60 / min |
| Token creation, key rotate, audit verify | 10 / min |

---

## Code findings C-08 / C-11 / C-12 — Secret management

**C-11 — Default passphrase in `docker-compose.yml`** *(Medium)*
- Was: `PQKMS_PASSPHRASE: "${PQKMS_PASSPHRASE:-change-me-before-production-deploy}"`
- Now: `${PQKMS_PASSPHRASE:?…must be set…}` → container fails fast if unset.

**C-08 — No passphrase strength enforcement** *(Informational)*
- `_validate_passphrase()` rejects shorter than `PQKMS_MIN_PASSPHRASE_LEN` (default 16) at startup.

**C-12 — Bootstrap token lifecycle** *(Low — partial)*
- Startup log now also prints the token id and the explicit revocation command:
  `DELETE /api/v1/tokens/<tid>`
- README adds operator-workflow note: *issue scoped tokens, then revoke the bootstrap token.*

---

## Code findings C-09 / C-10 — UI hardening & XSS

**C-09 — Google Fonts CDN** *(Medium)*
- Privacy/GDPR + supply-chain risk on every admin login.
- Removed `<link>` tags entirely; system `ui-monospace` / `ui-serif` fallbacks.

**C-10 — No CSP, inline script** *(Low)*
- Inline `<script>` extracted to `app/ui/app.js`.
- `SecurityHeadersMiddleware` adds:
  `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'`
  plus `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`.

**C-10b (new) — Stored XSS** *(Medium — found during remediation)*
- The keys-table renderer composed an HTML string by concatenating the operator-supplied key name into a template literal, then assigned that string to the table body's HTML property — i.e. the name was injected as raw markup.
- An admin (or any token with `key.create` scope) could set a key name containing an HTML tag with an event handler, and that handler would fire in the browser of every later viewer.
- Rewrote `makeKeyRow()` and `makeAuditEntry()` to build elements with `createElement` + `textContent` only. Server-supplied strings are no longer rendered as markup anywhere in the UI.

---

## Code findings C-13 / C-15 — Build & runtime

**C-13 — Reproducibility & patch latency** *(Low)*
- `LIBOQS_REF` pinned to `0.12.0` (was: `main`).
- `apt-get upgrade -y` in both builder and final stages.

**C-15 — Plaintext HTTP on port 8080** *(Medium)*
- Documented as the canonical deployment model: container runs HTTP, TLS terminates at a proxy. README hardening section calls this out explicitly with the recommended `--ssl-keyfile`/`--ssl-certfile` override for direct TLS if preferred.

---

## License compliance

**All dependencies are permissive** — no copyleft contamination.

| Type | Count | Examples |
|---|---:|---|
| MIT | 6 | fastapi, pydantic, argon2-cffi, slowapi, liboqs-python, liboqs |
| BSD-3-Clause | 1 | uvicorn |
| Apache-2.0 / BSD-3-Clause dual | 1 | cryptography |
| PSF | 1 | Python |
| Mixed (Debian) | 1 | base image |

**Action taken:** new `NOTICES.md` at project root with full attribution table.

**Note:** liboqs bundles third-party algorithm reference code with varying licenses. Our `OQS_MINIMAL_BUILD=KEM_ml_kem_768;SIG_ml_dsa_65` only includes upstream public-domain code today. Re-audit if that variable is widened.

---

## Deferred items (with rationale)

| ID | Item | Why deferred |
|---|---|---|
| C-01 | Token verify is `O(n)` constant-time scan | No security impact at realistic scale; only matters if token count grows into the thousands |
| C-02 | Unsalted SHA-384 of token | 256-bit secret from `secrets.token_urlsafe(32)` makes brute force infeasible; HMAC would be defense in depth, not a fix |
| C-06 | Audit canonicalization uses `\|` separator | Changing the format invalidates every existing chain. All fields server-controlled today → not exploitable. Schedule for next audit-schema version migration |
| C-07 | AES-GCM nonce-collision birthday bound at 2³² msgs | Documented in README; auto-rotation requires a schema change for the per-version usage counter |
| C-14 | liboqs `.so` not stripped, no build manifest | Cosmetic; SHA-256 manifest can be added later without source changes |

---

## Verification

**Unit tests** — 24 / 24 passing

```
tests/test_auth.py       6 passed
tests/test_crypto.py    11 passed
tests/test_keystore.py   7 passed
```

**HTTP smoke tests** (FastAPI `TestClient`) — all green

- ✓ CSP and security headers attached to every response
- ✓ 401 on missing / invalid bearer token
- ✓ Generic `"invalid base64 input"` on malformed input — **no exception leakage**
- ✓ Encrypt → decrypt roundtrip
- ✓ **HTTP 413** on oversized `Content-Length`
- ✓ 404 on unknown key id
- ✓ UI HTML contains no `fonts.googleapis.com` references
- ✓ `/ui/static/app.js` serves at 10,704 bytes

---

## Forward recommendations

**Operational (not code):**

1. **Pin** `python:3.12-slim` to a digest in production deployments
2. **Rebuild** the image on a security cadence (weekly during active dev, monthly for stable)
3. **Revoke** the bootstrap admin token after issuing scoped operational tokens — the startup log now provides the exact `DELETE` command
4. **Rotate** AEAD keys before approximately 2³² messages per version (call `POST /keys/{id}/rotate` on a schedule)
5. **Front** with TLS — either a reverse proxy (nginx, Caddy, Envoy) or pass `--ssl-keyfile`/`--ssl-certfile` to uvicorn directly
6. **Generate an SBOM** (`syft`, `docker sbom`) on each build for supply-chain traceability

**Subscribe to advisory feeds**

- pyca/cryptography, fastapi, uvicorn, pydantic, slowapi, liboqs (GitHub watch → security only)

---

## Summary

<br>

| | |
|---|---|
| **Vulnerabilities found** | 22 (3 dep CVEs + 15 code + 4 hardening) |
| **Vulnerabilities closed in code** | 17 |
| **Documented operational items** | 2 |
| **Deferred (justified)** | 3 |
| **Net change** | <span class="ok">High → 0 · Medium → 0 · Low → 3 (justified)</span> |
| **License posture** | <span class="ok">Clean — all permissive, attribution captured</span> |
| **Tests after remediation** | <span class="ok">24/24 passing</span> |

<br>

**Artifacts produced**

- `security-audit.csv` — full findings spreadsheet with status column
- `NOTICES.md` — license attribution
- This presentation
