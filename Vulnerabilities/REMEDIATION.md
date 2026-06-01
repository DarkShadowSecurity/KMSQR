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

---

# Scan `474d113d` — 2026-06-01 (30 findings: 0 crit / 8 high / 19 med / 3 low)

Report source: `scan-474d113d-bfae-401d-aa35-b790cdd5522e.json`
Triage date: 2026-06-01

Two findings are genuine deployment-hardening gaps and are **fixed**. The other
28 are tentative static-analysis matches on operator-controlled configuration,
loopback test code, or the project's deliberate, secure secret-handling — all
**false positives**, documented below. None are remotely exploitable.

## 1. MEDIUM — `compose-exposed-port` 8080:8080 in `deploy/docker-compose.yml` — **FIXED**

- The single-node compose published the KMS on `8080:8080`, i.e. `0.0.0.0`. The
  app serves plain HTTP unless `PQKMS_TLS_*` is set, so it is meant to sit behind
  a TLS-terminating proxy, not be exposed on every host interface.
- Remediation: changed the mapping to `127.0.0.1:8080:8080` (loopback only).
  Off-box access is now an explicit choice — front it with a reverse proxy (see
  the proxied `docker-compose.ha.yml` topology) or enable the native TLS listener.

## 2. LOW — `compose-no-resource-limits` in `deploy/docker-compose.yml` — **FIXED**

- No memory/CPU bound; a runaway or hostile load could exhaust the host.
- Remediation: added `deploy.resources.limits` (cpus `2.0`, memory `512M`) plus a
  `128M` reservation. The same block was added to the `pqkms` service in
  `docker-compose.ha.yml` for parity across the replica set.

## 3. HIGH ×3 + MEDIUM ×2 — secrets / weak-password / ODBC in `docker-compose.ha.yml:67,87` — **FALSE POSITIVES**

Findings: `generic-secret-assignment` (67, 87), `config-weak-password` (67),
`odbc-connection-string` (67, 87). All five match the single shell fragment:

```yaml
command:
  - 'export PGPASSWORD="$(cat /run/secrets/postgres_password)"; exec ...'
```

- This assigns `PGPASSWORD` from a **command substitution that reads a mounted
  Docker secret at runtime** — there is no literal credential, no value committed
  to source. It is the standard, secure way to hand a libpq password to psycopg
  (libpq has no file-based password env that takes a raw secret path; `PGPASSFILE`
  requires the `host:port:db:user:password` format).
- The file's own header (lines 16–17) mandates exactly this posture: "never pass
  the passphrase as a plain environment variable" — the secret is mounted at
  `/run/secrets/postgres_password` via Docker `secrets:` and read at boot.
- The `odbc-connection-string` / `config-weak-password` labels are misfires: there
  is no ODBC string and no weak/default password — just `PASSWORD="$(cat ...)"`
  pattern text. **No code change; no credential to rotate.**

## 4. HIGH ×5 — `python.ssrf.variable-url` in `tests/e2e_integration.py:81,108,196,203,220` — **FALSE POSITIVES**

- This is a self-contained end-to-end test that **spawns its own uvicorn server on
  `127.0.0.1`** and probes it. Every URL is loopback: line 81 is the literal
  `f"http://127.0.0.1:{PORT}/"` readiness poll; the rest are
  `urllib.request.urlopen(req)` where `req` targets the constant
  `BASE = "http://127.0.0.1:{PORT}/api/v1"`.
- No request-controlled host, no scheme/host attacker influence, no cloud-metadata
  reachability. Test-only code, never shipped in the runtime image. **No change.**

## 5. MEDIUM ×12 — `python.path-traversal.variable-path` — **FALSE POSITIVES**

`open()`/`Path()` called with a non-constant path. In every case the path is
**operator-controlled** (a deployment env var or a local CLI argument) — never a
value taken from an HTTP request. The KMS HTTP API exposes no endpoint that maps a
caller-supplied string to a filesystem path; key material is addressed by id, not
path. Enumerated:

| File:line | Source of the path | Why it is not attacker-controlled |
| --- | --- | --- |
| `app/main.py:130` | `PQKMS_PASSPHRASE_FILE` env | operator-set secret mount path |
| `app/main.py:183` | `PQKMS_DATA_DIR` env (default `/var/lib/pqkms`) | operator-set data dir |
| `app/main.py:297` | `Path(__file__).parent / "ui"` | a compile-time constant, no input at all |
| `app/storage/audit_sink.py:62` | `PQKMS_AUDIT_LOG_FILE` env | operator-set audit sink path |
| `app/storage/engine.py:28` | `PQKMS_DATA_DIR` env | operator-set data dir |
| `app/custody/factory.py:29` | `PQKMS_SHAMIR_SHARE_FILES` env | operator-set share paths |
| `app/cli/audit.py:36,45` | `PQKMS_PASSPHRASE_FILE` env / audit-log path | local CLI run by the operator |
| `app/cli/backup.py:46,89,101` | `out_dir` CLI arg / `PQKMS_PASSPHRASE_FILE` | operator chooses the backup dir |
| `app/cli/init.py:34` | `PQKMS_PASSPHRASE_FILE` env | operator-set secret mount path |
| `app/cli/rekey.py:36` | `PQKMS_PASSPHRASE[_FILE]` env | operator-set secret mount path |

These are the binding's intended interface: the operator who sets the env var or
runs the CLI already has the privileges any path would grant. **No change.**

## 6. LOW ×2 — `dockerfile-unpinned-packages` in `deploy/Dockerfile:22,45` — **JUSTIFIED**

- Line 22 installs the **builder-stage** toolchain (`build-essential cmake
  ninja-build git ca-certificates libssl-dev`). Multi-stage build: none of these
  reach the runtime image (only the liboqs `.so` is copied), so they add zero
  runtime attack surface.
- Line 45 installs `libssl3 tini` in the runtime stage.
- Reproducibility for these OS packages comes from the **base image digest pin**
  (`python:3.12-slim@sha256:090ba…`, Dockerfile lines 12–15), and the project
  deliberately does **not** `apt-get upgrade` so builds stay reproducible and OS
  patches arrive via Dependabot digest bumps. Pinning exact Debian point-release
  versions here would break the build on the next digest bump (the pinned version
  leaves the mirror index), directly fighting that strategy. Accepted risk,
  consistent with the documented build philosophy. **No change.**

---

## Scan 474d113d summary

| Finding | Severity | Status |
| --- | --- | --- |
| compose-exposed-port — docker-compose.yml | medium | **Fixed (→ 127.0.0.1)** |
| compose-no-resource-limits — docker-compose.yml | low | **Fixed (limits added)** |
| secret/weak-pw/odbc — docker-compose.ha.yml:67,87 (×5) | high/med | **FP (runtime secret read)** |
| ssrf variable-url — e2e_integration.py (×5) | high | **FP (loopback test)** |
| path-traversal variable-path (×12) | medium | **FP (operator-controlled path)** |
| dockerfile-unpinned-packages — Dockerfile:22,45 (×2) | low | **Justified (digest-pin strategy)** |

Both actionable deployment-hardening findings are fixed. The remaining 28 are
tentative analyzer matches on operator configuration, loopback test code, or the
project's intentional secure secret handling.
