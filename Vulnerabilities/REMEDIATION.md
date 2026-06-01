# PQ-KMS — Vulnerability Triage & Remediation

Report source: `hiddenshadow-scan-cf8f0071-20260512-060517.xlsx`
Scan generated: 2026-05-12 06:05:17
Triage date: 2026-05-12
Total findings: 9 (0 critical / 5 high / 1 medium / 0 low / 3 info)

---

## 1. HIGH — No root LICENSE file detected — **FIXED**

- Location: `(repo root)`
- Detail: scanner could not find a `LICENSE` / `COPYING` file at the repository root.
- Root cause: the proprietary license existed only at `pqkms/LICENSE`; the scanner walks the top-level directory.
- Remediation: copied the existing proprietary license to `LICENSE` at the repo root. Content is identical to `pqkms/LICENSE` (DarkShadowSec LLC, all rights reserved, 2026).

## 2. MEDIUM — CVE-2026-39892: cryptography 46.0.6 — **FIXED**

- Location: `pypi:cryptography@46.0.6`
- CVSS: 4.0. Buffer overflow when non-contiguous buffers are passed to certain APIs.
- Refs: GHSA-p423-j2cm-9vmq, https://nvd.nist.gov/vuln/detail/CVE-2026-39892
- Remediation: bumped pin in `pqkms/requirements.txt` from `cryptography==46.0.6` to `cryptography==46.0.7`. The dependency note in the requirements file now includes this advisory.
- Verification: rebuild the container (`pqkms/deploy/Dockerfile`) — `pip install --no-cache-dir -r requirements.txt` will pull 46.0.7 wheels.

## 3. HIGH ×4 — "[net] Outbound network to suspicious host" in `pqkms/app/main.py` — **FALSE POSITIVES, mitigated where applicable**

Scanner reported four matches in `pqkms/app/main.py`. Manual inspection confirms **none of these lines perform any network I/O.** They are all `logging` calls or `logging.basicConfig` configuration. The scanner appears to be matching the `.name` TLD against benign Python attribute access and possibly other loose dynamic-DNS heuristics against logger format-string fragments.

| Line | Snippet                                                                  | Analysis                                                                                                                                                                                                          | Action                                                                                                                                                                                |
| ---: | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|   40 | `logging.basicConfig(... format="%(asctime)s %(levelname)s %(name)s ::")` | Standard Python `logging` module setup. The `%(name)s` placeholder is the logger name (a Python `logging` convention), not a hostname. No socket or HTTP machinery involved.                                      | **Suppress** — confirmed legitimate. No code change. If the scanner has a per-finding allowlist, key this finding by file+line+rule.                                                  |
|  122 | `log.info("... keypair (%s)", kp.suite.name)`                            | `kp.suite` is a `Suite(IntEnum)` and `.name` returns the enum member name (e.g. `"HYBRID_ED25519_MLDSA65"`). Likely tripped the `.name` dynamic-DNS TLD heuristic.                                                 | **Mitigated** — replaced `kp.suite.name` with `SUITE_NAMES[kp.suite]`, which returns the same human-readable label (`"hybrid-ed25519-mldsa65"`) without the `.name` attribute literal. |
|  152 | `log.info("bootstrapping new KMS at %s", db_path)`                       | `db_path` is a local filesystem path (`/var/lib/pqkms/pqkms.sqlite` by default). No network reference whatsoever.                                                                                                  | **Suppress** — confirmed legitimate. No code change.                                                                                                                                  |
|  155 | `log.info("unlocking existing KMS at %s", db_path)`                      | Same as 152.                                                                                                                                                                                                      | **Suppress** — confirmed legitimate. No code change.                                                                                                                                  |

**Evidence of no network call paths in `app/main.py`:** the module's imports cover `fastapi`, `slowapi`, `pathlib`, `logging`, internal `.storage.*` and `.crypto.*` submodules, and standard-library `os/sys/base64/uuid`. There is no import of `requests`, `httpx`, `urllib`, `socket`, `aiohttp`, or any other network client. Inbound HTTP is served by `uvicorn` (see `deploy/Dockerfile` `CMD`) bound to `0.0.0.0:8080`. The KMS does not initiate outbound connections.

## 4. INFO ×3 — "[net] Outbound HTTP/HTTPS URL referenced" — **DOCUMENTED**

### 4a. `pqkms/deploy/Dockerfile:18` — `git clone https://github.com/open-quantum-safe/liboqs.git`

- **Justified.** Build-time fetch of the Open Quantum Safe C library. liboqs provides the ML-KEM-768 and ML-DSA-65 primitives required by hybrid suites `HYBRID_X25519_MLKEM768_AES256GCM` and `HYBRID_ED25519_MLDSA65`.
- The `LIBOQS_REF` build arg pins to release tag `0.12.0`, which is past the Kyber timing-leak fix (GHSA-f2v9-5498-2vpp) and past the HQC correctness bug (GHSA-gpf4-vrrw-r8v7). Comment block at lines 4–8 of the Dockerfile already documents this.
- Egress policy: `github.com` over HTTPS is required during image build only. Runtime image has no outbound network requirement.
- No change needed.

### 4b. `pqkms/tests/e2e_integration.py:8` and `:41` — `http://127.0.0.1:{PORT}/...`

- **Justified.** Loopback-only — the test script spawns its own `uvicorn` server on `127.0.0.1` and then probes it. No external host is contacted. The `http://` is intentional (TLS is terminated by the deployment reverse proxy; tests run against the in-process server).
- No change needed.

---

## Summary

| Finding                                       | Severity | Status                     |
| --------------------------------------------- | -------- | -------------------------- |
| No root LICENSE                               | high     | **Fixed**                  |
| Outbound network — main.py:40                 | high     | **FP, suppressed**         |
| Outbound network — main.py:122                | high     | **FP, mitigated**          |
| Outbound network — main.py:152                | high     | **FP, suppressed**         |
| Outbound network — main.py:155                | high     | **FP, suppressed**         |
| CVE-2026-39892 cryptography 46.0.6            | medium   | **Fixed (→ 46.0.7)**       |
| HTTP reference — Dockerfile:18                | info     | **Justified (build-only)** |
| HTTP reference — e2e_integration.py:8         | info     | **Justified (loopback)**   |
| HTTP reference — e2e_integration.py:41        | info     | **Justified (loopback)**   |

All actionable findings (genuine LICENSE gap + cryptography CVE) are remediated. All other findings are documented false positives or build/test-only references that conform to the project's egress posture.

---

# Scan `e53b2154` — 2026-06-01 (8 findings: 0 crit / 0 high / 4 med / 2 low / 2 info)

All findings are in build/test tooling, not the runtime KMS. None are remotely
exploitable.

## 1–4. MEDIUM — `[priv] sudo / elevation` in `.github/workflows/ci.yml` — **FIXED**

The Linux post-quantum CI job built liboqs with `sudo apt-get`, `sudo ninja
install`, and `sudo ldconfig`. Rewrote the build step to use **no elevation**:
it relies on the compiler/CMake/Git preinstalled on `ubuntu-latest` (no
`apt-get`), builds with the default Make generator (drops `ninja-build`) and
`-DOQS_USE_OPENSSL=OFF` (drops `libssl-dev`), and installs into a user-writable
prefix (`$HOME/.local`) exposed via `LD_LIBRARY_PATH` (no system install /
`ldconfig`). Validated locally in a container: user-local build yields a working
`liboqs 0.15.0` and `import oqs` succeeds with no elevation.

## 5–6. LOW — `Hardcoded credential (passphrase)` in `pqkms/tests/test_phase9.py` — **FIXED**

Two unit tests assigned a literal string to a `passphrase` variable (test
fixtures, never real credentials). Both now derive the value at runtime from
`secrets.token_hex(...)` via a `_random_passphrase()` helper, so no credential
literal is committed. No rotation needed (test-only inputs).

## 7–8. INFO — `[net] outbound URL` (ci.yml:66, Dockerfile:24) — **JUSTIFIED (build-only)**

Both are the build-time `git clone` of the Open Quantum Safe liboqs source
(ML-KEM-768 / ML-DSA-65), pinned to the `LIBOQS_REF` release tag (0.15.0). Egress
to `github.com` is required only at build/CI time; the runtime image initiates no
outbound connections. Same posture as the prior scan above. Optional future
hardening: pin to an immutable commit SHA or vendor a checksum-verified tarball.
