# Security Policy

PQ-KMS is a cryptographic key-management system. We take security reports
seriously and appreciate responsible disclosure.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅        |
| < 1.0   | ❌        |

Only the latest minor release receives security fixes. Pin to a tagged
release and rebuild on a regular cadence to pick up patched dependencies.

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Please report privately using **GitHub Private Vulnerability Reporting**:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Provide a description, affected version/commit, reproduction steps, and
   (if known) impact and a suggested fix.

If you cannot use the GitHub workflow, email **kip@darkshadowsec.com**
with the same details. Encrypt sensitive reports if possible.

### What to expect

- **Acknowledgement:** within 3 business days.
- **Triage & severity assessment:** within 10 business days.
- **Fix or mitigation plan:** communicated after triage; timelines depend on
  severity and complexity.
- **Disclosure:** coordinated. We will credit you in the release notes unless
  you prefer to remain anonymous.

## Scope

In scope:

- The PQ-KMS application code (`pqkms/app/**`): crypto layer, API, auth, storage.
- Deployment artifacts (`pqkms/deploy/**`): Dockerfile, compose.
- Cryptographic design flaws (key handling, KDF/KEM/AEAD/signature misuse,
  audit-log integrity, token authentication).

Out of scope:

- Vulnerabilities in third-party dependencies that already have a public
  advisory and a released fix — instead, confirm we have updated the pin and
  open a normal PR/issue.
- Findings that require a pre-compromised host, physical access, or a
  misconfigured deployment that contradicts the hardening guidance in the
  README.
- Reports from automated scanners without a demonstrated, exploitable impact.

## Hardening guidance

This project ships a **reference implementation**. Before trusting it with real
secrets, follow the "Production hardening notes" in
[`pqkms/README.md`](pqkms/README.md): terminate TLS at a hardened reverse proxy,
move the Root KEK into an HSM or external secrets manager, revoke the bootstrap
admin token after issuing scoped tokens, and stream audit logs to append-only
storage.

## Cryptographic dependencies

Post-quantum primitives come from [liboqs](https://github.com/open-quantum-safe/liboqs)
(ML-KEM-768 / ML-DSA-65) and [`cryptography`](https://github.com/pyca/cryptography)
(classical primitives, AEAD, KDF). Both are version-pinned in
`pqkms/requirements.txt` and the Dockerfile; Dependabot monitors them for
advisories.
