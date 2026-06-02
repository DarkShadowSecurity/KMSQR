# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""SBOM generator: parses pinned requirements into a valid CycloneDX document."""
from pathlib import Path

from app.cli.sbom import parse_requirements, build_sbom, _PROJECT_ROOT


def test_parse_requirements_pins_only():
    text = "\n".join([
        "# a comment",
        "fastapi==0.136.3",
        "uvicorn[standard]==0.48.0",
        "liboqs-python==0.15.0 ; platform_system != 'Windows'",
        "-r other.txt",
        "unpinned-pkg",
        "",
    ])
    parsed = dict(parse_requirements(text))
    assert parsed["fastapi"] == "0.136.3"
    assert parsed["uvicorn"] == "0.48.0"             # extras stripped
    assert parsed["liboqs-python"] == "0.15.0"        # env marker ignored
    assert "unpinned-pkg" not in parsed              # no version -> skipped
    assert "other.txt" not in parsed                 # -r include line skipped


def test_build_sbom_shape_is_valid_cyclonedx():
    sbom = build_sbom([_PROJECT_ROOT / "requirements.txt"])
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["metadata"]["component"]["name"] == "pqkms"
    assert "timestamp" not in sbom["metadata"]        # deterministic by default
    names = {c["name"] for c in sbom["components"]}
    assert {"fastapi", "cryptography", "alembic"}.issubset(names)
    for c in sbom["components"]:
        assert c["type"] == "library"
        assert c["purl"].startswith("pkg:pypi/")


def test_build_sbom_deduplicates_across_files(tmp_path):
    a = tmp_path / "a.txt"; a.write_text("foo==1.0\nbar==2.0\n")
    b = tmp_path / "b.txt"; b.write_text("foo==9.9\nbaz==3.0\n")
    sbom = build_sbom([a, b])
    versions = {c["name"]: c["version"] for c in sbom["components"]}
    assert versions == {"foo": "1.0", "bar": "2.0", "baz": "3.0"}  # first wins, deduped


def test_timestamp_included_when_given():
    sbom = build_sbom([_PROJECT_ROOT / "requirements.txt"], timestamp="2026-06-02T00:00:00Z")
    assert sbom["metadata"]["timestamp"] == "2026-06-02T00:00:00Z"
