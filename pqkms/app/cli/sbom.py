# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Generate a CycloneDX 1.5 SBOM (Software Bill of Materials) for PQ-KMS from its
pinned requirements files. Dependency-free and deterministic so it runs in CI
without extra tooling and produces stable output for diffing/attestation.

    python -m app.cli.sbom                       # SBOM of requirements.txt -> stdout
    python -m app.cli.sbom --all -o sbom.json    # include ha + custody extras
    python -m app.cli.sbom --timestamp 2026-06-02T00:00:00Z

The result is valid CycloneDX JSON that downstream tooling (Grype, Dependency-
Track, GitHub dependency review) and provenance attestation can consume. See
deploy/RELEASE.md for signing the image + attaching this SBOM as an attestation.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Optional

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)")
_PROJECT_ROOT = Path(__file__).resolve().parents[2]  # pqkms/


def parse_requirements(text: str) -> list[tuple[str, str]]:
    """Extract (name, version) for each pinned (== ) requirement. Comments, blank
    lines, unpinned entries and environment markers are ignored for the version."""
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        m = _REQ_LINE.match(stripped)
        if m:
            out.append((m.group(1).lower(), m.group(2)))
    return out


def _component(name: str, version: str) -> dict:
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{name}@{version}",
        "bom-ref": f"pkg:pypi/{name}@{version}",
    }


def build_sbom(req_files: list[Path], *, timestamp: Optional[str] = None) -> dict:
    seen: dict[str, str] = {}
    for f in req_files:
        if not f.exists():
            continue
        for name, version in parse_requirements(f.read_text(encoding="utf-8")):
            seen.setdefault(name, version)
    components = [_component(n, v) for n, v in sorted(seen.items())]
    metadata: dict = {
        "component": {
            "type": "application",
            "name": "pqkms",
            "version": "1.0.0",
            "purl": "pkg:generic/pqkms@1.0.0",
        },
        "tools": [{"vendor": "DarkShadowSec", "name": "pqkms-sbom", "version": "1.0.0"}],
    }
    if timestamp:
        metadata["timestamp"] = timestamp
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Generate a CycloneDX SBOM for PQ-KMS.")
    ap.add_argument("--all", action="store_true", help="include requirements-ha.txt and requirements-custody.txt")
    ap.add_argument("-o", "--output", help="write to this file instead of stdout")
    ap.add_argument("--timestamp", help="ISO8601 timestamp to embed (omit for deterministic output)")
    args = ap.parse_args(argv)

    files = [_PROJECT_ROOT / "requirements.txt"]
    if args.all:
        files += [_PROJECT_ROOT / "requirements-ha.txt", _PROJECT_ROOT / "requirements-custody.txt"]
    sbom = build_sbom(files, timestamp=args.timestamp)
    text = json.dumps(sbom, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
