# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""Phase 8: operator passphrase rotation (Root-KEK re-seal) and backup/verify."""
import base64

import pytest
from sqlalchemy import text

from app.storage.repository import make_repository
from app.storage.keystore import KeyStore
from app.storage.audit import AuditLog, load_or_create_audit_signing_key
from app.custody import PassphraseCustodian
from app.cli import backup as backup_cli


def _repo(tmp_path, name="test.db"):
    return make_repository(f"sqlite:///{(tmp_path / name).as_posix()}")


def test_rekey_preserves_subordinate_keys(tmp_path):
    repo = _repo(tmp_path)
    ks = KeyStore(repo, PassphraseCustodian("old-operator-passphrase"))
    ks.initialize()
    k = ks.create_key("data", "aead")
    enc = ks.encrypt(k.id, b"protected before rekey")
    old_root = ks._root_kek

    # Rotate the passphrase (re-seal the same Root KEK).
    ks.rewrap_root_kek(PassphraseCustodian("new-operator-passphrase"))
    assert ks._root_kek == old_root  # Root KEK itself is unchanged

    # Old passphrase no longer unlocks; new one does, and old ciphertext decrypts.
    with pytest.raises(ValueError):
        KeyStore(repo, PassphraseCustodian("old-operator-passphrase")).unlock()
    reopened = KeyStore(repo, PassphraseCustodian("new-operator-passphrase"))
    reopened.unlock()
    assert reopened.decrypt(k.id, enc["ciphertext"]) == b"protected before rekey"


def test_rekey_migrates_legacy_db(tmp_path):
    # A legacy-format DB (no custody envelope row) becomes a current-format DB
    # after rekey, and unlocks with the new passphrase.
    repo = _repo(tmp_path, "legacy.db")
    from app.crypto.aead import AEAD
    from app.crypto.kdf import derive_from_passphrase
    salt = b"\x11" * 32
    wk = derive_from_passphrase("legacy-pass-123456", salt)
    root = AEAD.generate_key()
    repo.put_meta("root_kek_salt", salt)
    repo.put_meta("root_kek_wrapped", AEAD.encrypt(wk, root, aad=b"pqkms/root-kek/v1"))

    ks = KeyStore(repo, PassphraseCustodian("legacy-pass-123456"))
    ks.unlock()
    ks.rewrap_root_kek(PassphraseCustodian("brand-new-passphrase-1"))
    assert repo.get_meta(KeyStore.META_CUSTODY) is not None  # migrated to envelope format

    reopened = KeyStore(repo, PassphraseCustodian("brand-new-passphrase-1"))
    reopened.unlock()
    assert reopened._root_kek == root


def test_backup_create_and_verify_roundtrip(tmp_path, monkeypatch):
    src = tmp_path / "data"
    src.mkdir()
    monkeypatch.setenv("PQKMS_DATA_DIR", str(src))
    monkeypatch.setenv("PQKMS_PASSPHRASE", "backup-test-passphrase-1")
    monkeypatch.delenv("PQKMS_DB_URL", raising=False)

    # Populate a KMS at the default sqlite path under PQKMS_DATA_DIR.
    repo = make_repository(data_dir=str(src))
    ks = KeyStore(repo, PassphraseCustodian("backup-test-passphrase-1"))
    ks.initialize()
    audit = AuditLog(repo, load_or_create_audit_signing_key(ks))
    for i in range(4):
        audit.append("svc", "act", target=f"t{i}", detail={"i": i})

    out = tmp_path / "backup"
    assert backup_cli.cmd_create(str(out)) == 0
    assert (out / "manifest.json").exists()
    assert (out / "pqkms.sqlite").exists()

    # A clean snapshot verifies.
    assert backup_cli.cmd_verify(str(out)) == 0

    # Tampering the snapshot's audit table is detected.
    snap_repo = make_repository(f"sqlite:///{(out / 'pqkms.sqlite').as_posix()}")
    with snap_repo.engine.begin() as c:
        c.execute(text("UPDATE audit_log SET detail='{\"i\": 999}' WHERE seq=2"))
    assert backup_cli.cmd_verify(str(out)) == 1
