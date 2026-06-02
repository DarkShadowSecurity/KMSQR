# PQ-KMS Release & Supply-Chain Procedure

How a release is built, attested, and signed. The SBOM step is automated; image
signing and provenance are documented here as a ready-to-enable procedure (the
repository policy is to **pin every GitHub Action by commit SHA** and verify
downloaded tool binaries by SHA-256 — see `.github/workflows/gitleaks.yml` — so
those steps are intentionally left for the maintainer to wire with verified
digests rather than shipped with unpinned references).

## SBOM (automated)

A CycloneDX 1.5 SBOM of the pinned dependencies is generated on every CI run:

```bash
python -m app.cli.sbom --all -o sbom.cdx.json
```

The generator is dependency-free and deterministic (see `app/cli/sbom.py`), so
the SBOM diffs cleanly across releases and can be attached as an attestation.

## Recommended release steps

1. **Tag** a release (`vX.Y.Z`).
2. **Build** the image from the digest-pinned base (`deploy/Dockerfile`).
3. **Generate** the SBOM (above) and the image SBOM (e.g. Syft) — pin the tool by
   version and verify its release SHA-256, mirroring the gitleaks workflow.
4. **Sign** the image and **attest** SBOM + build provenance with cosign
   (keyless OIDC signing) and SLSA provenance. Pin `sigstore/cosign-installer`
   and any attestation actions by commit SHA.
5. **Verify** before promotion:
   ```bash
   cosign verify <image> --certificate-identity-regexp '...' \
       --certificate-oidc-issuer https://token.actions.githubusercontent.com
   cosign verify-attestation --type cyclonedx <image>
   ```
6. **Publish** to GHCR and record the digest in the release notes.

## Consuming the SBOM

- Scan for known vulns: `grype sbom:sbom.cdx.json`.
- Track over time: upload to Dependency-Track.
- GitHub: enable dependency review / Dependabot (already configured) to catch
  advisories in pinned dependencies.

## Why these steps aren't pre-wired

This repo pins all actions and tool binaries by immutable digest for
reproducibility and tamper resistance. Shipping a signing workflow with
tag-pinned (mutable) action references would regress that posture, and
fabricating digests offline would be worse. Wire the steps above with digests
verified at authoring time; Dependabot then keeps them current.
