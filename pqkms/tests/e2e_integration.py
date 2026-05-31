#!/usr/bin/env python3
# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""End-to-end HTTP integration test for PQ-KMS. Self-contained — spawns its own server.

Cross-platform: uses a temp data dir / log file (no hard-coded /tmp) and a
portable process-group teardown so it runs on Windows as well as POSIX. The
PQ-availability assertion is gated on liboqs being importable, so the suite
still passes on a classical-only host (e.g. Windows dev box without liboqs);
it prints a clear warning instead of failing in that case.
"""
import os, sys, base64, json, time, shutil, signal, subprocess, tempfile, urllib.request, urllib.error, re

# Windows consoles default to cp1252 and choke on the ✓/✗ glyphs. Prefer UTF-8;
# fall back to ASCII marks if the stream still can't encode them.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass
_UNICODE_OK = (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "") in ("utf8", "utf16", "utf32")
MARK_OK = "\033[32m✓\033[0m" if _UNICODE_OK else "\033[32m[OK]\033[0m"
MARK_BAD = "\033[31m✗\033[0m" if _UNICODE_OK else "\033[31m[XX]\033[0m"

PORT = int(os.environ.get("PQKMS_E2E_PORT", "8080"))
BASE = f"http://127.0.0.1:{PORT}/api/v1"
_TMP = tempfile.mkdtemp(prefix="pqkms-e2e-")
DATA_DIR = os.path.join(_TMP, "data")
LOG_FILE = os.path.join(_TMP, "server.log")

# Is liboqs available here? Drives whether we *require* PQ to be active.
try:
    import oqs  # noqa: F401
    PQ_EXPECTED = True
except Exception:
    PQ_EXPECTED = False

# ---- spawn server ----
shutil.rmtree(DATA_DIR, ignore_errors=True)
os.makedirs(DATA_DIR, exist_ok=True)
env = {**os.environ, "PQKMS_DATA_DIR": DATA_DIR, "PQKMS_PASSPHRASE": "e2e-test-passphrase-16+", "PYTHONWARNINGS": "ignore"}
# On a classical-only host (no liboqs) the server would refuse to start with
# PQKMS_REQUIRE_PQ on (the default), so opt out explicitly for the e2e run.
if not PQ_EXPECTED:
    env["PQKMS_REQUIRE_PQ"] = "0"
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
logf = open(LOG_FILE, "w")
# start_new_session (POSIX) / CREATE_NEW_PROCESS_GROUP (Windows) put the child
# in its own group so we can tear it down cleanly on either platform.
_popen_kwargs = {}
if os.name == "nt":
    _popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
else:
    _popen_kwargs["start_new_session"] = True
proc = subprocess.Popen(
    [sys.executable, "-W", "ignore", "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORT)],
    cwd=repo_root, env=env, stdout=logf, stderr=subprocess.STDOUT,
    **_popen_kwargs,
)
print(f"Spawned server pid={proc.pid} (PQ_EXPECTED={PQ_EXPECTED})")

def shutdown():
    try:
        if os.name == "nt":
            proc.terminate()  # no killpg on Windows; uvicorn runs in-process here
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        try: proc.kill()
        except Exception: pass
    logf.close()
    shutil.rmtree(_TMP, ignore_errors=True)

import atexit
atexit.register(shutdown)

# ---- wait for readiness ----
start = time.time()
while time.time() - start < 15:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=1) as r:
            if r.status == 200:
                break
    except Exception:
        time.sleep(0.3)
else:
    print("Server failed to start. Log:")
    print(open(LOG_FILE).read())
    sys.exit(1)

# ---- grab bootstrap token ----
log_text = open(LOG_FILE).read()
m = re.search(r'pqkms_[A-Za-z0-9_-]+', log_text)
if not m:
    print("Bootstrap token not found in log:")
    print(log_text)
    sys.exit(1)
TOKEN = m.group(0)
print(f"Bootstrap token: {TOKEN[:22]}…\n")

def call(method, path, body=None):
    req = urllib.request.Request(
        BASE + path, method=method,
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
        data=json.dumps(body).encode() if body is not None else None,
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

def b64e(s): return base64.b64encode(s if isinstance(s, bytes) else s.encode()).decode()
def b64d(s): return base64.b64decode(s)

def check(name, cond, detail=""):
    mark = MARK_OK if cond else MARK_BAD
    print(f"  {mark} {name}" + (f"  ({detail})" if detail else ""))
    if not cond: sys.exit(1)

print("\n=== PQ-KMS end-to-end integration test ===\n")

# 1. Status
print("1. Service status")
s, r = call("GET", "/status")
check("GET /status returns 200", s == 200)
check("KMS is unlocked", r["unlocked"])
if PQ_EXPECTED:
    check("PQ algorithms available", r["pq_available"], "ML-KEM-768 + ML-DSA-65")
else:
    print("  \033[33m!\033[0m liboqs not present — running classical-only (PQ assertions skipped)")

# 2. Create each key type
print("\n2. Key creation")
s, aead_key = call("POST", "/keys", {"name": "data-encryption", "key_type": "aead"})
check("create AEAD key", s == 200, f"id={aead_key['id'][:8]}…")
s, sig_key = call("POST", "/keys", {"name": "signing-authority", "key_type": "sig"})
check("create Sig key", s == 200, f"suite={sig_key['suite']}")
s, kem_key = call("POST", "/keys", {"name": "key-wrapper", "key_type": "kem"})
check("create KEM key", s == 200, f"pub_bytes={len(b64d(kem_key['public_material']))}")

# 3. List
print("\n3. Listing")
s, keys = call("GET", "/keys")
check("GET /keys returns 200", s == 200)
check("all 3 keys listed", len(keys) == 3)

# 4. AEAD encrypt/decrypt roundtrip
print("\n4. AEAD encrypt/decrypt")
plaintext = "The launch codes are 1-2-3-4-5."
s, enc = call("POST", f"/keys/{aead_key['id']}/encrypt", {"plaintext_b64": b64e(plaintext)})
check("encrypt returns 200", s == 200, f"version={enc['version']}")
s, dec = call("POST", f"/keys/{aead_key['id']}/decrypt", {"ciphertext_b64": enc["ciphertext"]})
check("decrypt returns 200", s == 200)
check("plaintext roundtrips exactly", b64d(dec["plaintext_b64"]).decode() == plaintext)

# 5. Rotation preserves old versions
print("\n5. Key rotation")
s, rotated = call("POST", f"/keys/{aead_key['id']}/rotate")
check("rotate returns 200", s == 200)
check("version incremented", rotated["current_version"] == 2)
# encrypt under new version
s, enc2 = call("POST", f"/keys/{aead_key['id']}/encrypt", {"plaintext_b64": b64e("post-rotation data")})
check("new encryption uses v2", enc2["version"] == 2)
# old ciphertext still decrypts
s, dec_old = call("POST", f"/keys/{aead_key['id']}/decrypt", {"ciphertext_b64": enc["ciphertext"]})
check("pre-rotation ciphertext still decrypts", s == 200 and b64d(dec_old["plaintext_b64"]).decode() == plaintext)

# 6. Hybrid sign/verify
print("\n6. Hybrid sign/verify (Ed25519 + ML-DSA-65)")
msg = "treaty signed by both parties"
s, signed = call("POST", f"/keys/{sig_key['id']}/sign", {"message_b64": b64e(msg)})
check("sign returns 200", s == 200, f"sig bytes={len(b64d(signed['signature']))}")
s, v = call("POST", f"/keys/{sig_key['id']}/verify", {"message_b64": b64e(msg), "signature_b64": signed["signature"]})
check("valid sig verifies", v["valid"])
s, v = call("POST", f"/keys/{sig_key['id']}/verify", {"message_b64": b64e("tampered"), "signature_b64": signed["signature"]})
check("tampered message rejected", not v["valid"])

# 7. Hybrid KEM wrap/unwrap
print("\n7. Hybrid KEM wrap/unwrap (X25519 + ML-KEM-768)")
data_key = os.urandom(32)
s, wrapped = call("POST", f"/keys/{kem_key['id']}/wrap", {"data_key_b64": b64e(data_key)})
check("wrap returns 200", s == 200, f"encap bytes={len(b64d(wrapped['encapsulation']))}")
s, unwrapped = call("POST", f"/keys/{kem_key['id']}/unwrap",
                     {"encapsulation_b64": wrapped["encapsulation"], "wrapped_key_b64": wrapped["wrapped_key"]})
check("unwrap returns 200", s == 200)
check("data key roundtrips exactly", b64d(unwrapped["data_key_b64"]) == data_key)

# 8. Token scoping
print("\n8. Token scoping")
s, tok = call("POST", "/tokens", {"name": "read-only-service", "scopes": ["read"]})
check("issue scoped token", s == 200)
ro_token = tok["token"]
# Use the restricted token
req = urllib.request.Request(BASE + "/keys", headers={"Authorization": f"Bearer {ro_token}"})
with urllib.request.urlopen(req) as r:
    check("scoped token can read", r.status == 200)
# Try to use it for an admin action
req = urllib.request.Request(BASE + "/keys", method="POST",
    headers={"Authorization": f"Bearer {ro_token}", "Content-Type": "application/json"},
    data=json.dumps({"name": "should-fail", "key_type": "aead"}).encode())
try:
    urllib.request.urlopen(req)
    check("read-only token blocked from create", False)
except urllib.error.HTTPError as e:
    check("read-only token blocked from create", e.code == 403)

# 9. Audit log
print("\n9. Audit log integrity")
s, audit = call("GET", "/audit?limit=50")
check("GET /audit returns 200", s == 200)
check("audit log has entries", len(audit["entries"]) > 0, f"{len(audit['entries'])} entries")
s, chain = call("GET", "/audit/verify")
check("audit chain is valid", chain["valid"], "all hash-chain links + hybrid signatures OK")

# 10. Auth denial
print("\n10. Authentication")
req = urllib.request.Request(BASE + "/keys", headers={"Authorization": "Bearer invalid-token"})
try:
    urllib.request.urlopen(req)
    check("invalid token rejected", False)
except urllib.error.HTTPError as e:
    check("invalid token rejected", e.code == 401)

print(f"\n{MARK_OK} All end-to-end checks passed.\n")
