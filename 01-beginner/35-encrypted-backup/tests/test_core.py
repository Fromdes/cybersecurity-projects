"""Tests for project_35.core — Encrypted Backup Tool."""
from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from project_35.core import (
    MAGIC,
    create_backup,
    derive_key,
    restore_backup,
    verify_backup,
)


def _make_source(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "file1.txt").write_text("hello world")
    (src / "file2.txt").write_text("secret data")
    sub = src / "subdir"
    sub.mkdir()
    (sub / "nested.txt").write_text("nested content")
    return src


class TestDeriveKey:
    def test_length(self) -> None:
        assert len(derive_key("pw", b"0123456789abcdef")) == 32

    def test_deterministic(self) -> None:
        salt = b"0123456789abcdef"
        assert derive_key("pw", salt) == derive_key("pw", salt)


class TestCreateBackup:
    def test_creates_file(self, tmp_path: Path) -> None:
        src = _make_source(tmp_path)
        out = tmp_path / "backup.encbak"
        create_backup(src, out, "password")
        assert out.exists()

    def test_magic_bytes(self, tmp_path: Path) -> None:
        src = _make_source(tmp_path)
        out = tmp_path / "backup.encbak"
        create_backup(src, out, "password")
        assert out.read_bytes()[:8] == MAGIC

    def test_manifest_created(self, tmp_path: Path) -> None:
        src = _make_source(tmp_path)
        out = tmp_path / "backup.encbak"
        create_backup(src, out, "password")
        assert (tmp_path / "backup.manifest.json").exists()

    def test_file_count_in_manifest(self, tmp_path: Path) -> None:
        src = _make_source(tmp_path)
        out = tmp_path / "backup.encbak"
        manifest = create_backup(src, out, "password")
        assert manifest.file_count == 3

    def test_single_file_backup(self, tmp_path: Path) -> None:
        f = tmp_path / "secret.txt"
        f.write_text("my secret")
        out = tmp_path / "backup.encbak"
        manifest = create_backup(f, out, "pw")
        assert manifest.file_count == 1

    def test_missing_source_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            create_backup(tmp_path / "nonexistent", tmp_path / "out.encbak", "pw")

    def test_empty_password_raises(self, tmp_path: Path) -> None:
        src = _make_source(tmp_path)
        with pytest.raises(ValueError, match="password"):
            create_backup(src, tmp_path / "out.encbak", "")

    def test_file_permissions_600(self, tmp_path: Path) -> None:
        src = _make_source(tmp_path)
        out = tmp_path / "backup.encbak"
        create_backup(src, out, "pw")
        mode = out.stat().st_mode & 0o777
        assert mode == 0o600


class TestRestoreBackup:
    def test_restore_roundtrip(self, tmp_path: Path) -> None:
        src = _make_source(tmp_path)
        out = tmp_path / "backup.encbak"
        create_backup(src, out, "mypassword")
        restore_dir = tmp_path / "restored"
        count = restore_backup(out, restore_dir, "mypassword")
        assert count == 3

    def test_restore_content_matches(self, tmp_path: Path) -> None:
        src = _make_source(tmp_path)
        out = tmp_path / "backup.encbak"
        create_backup(src, out, "mypassword")
        restore_dir = tmp_path / "restored"
        restore_backup(out, restore_dir, "mypassword")
        restored = list(restore_dir.rglob("*.txt"))
        assert len(restored) == 3

    def test_wrong_password_raises(self, tmp_path: Path) -> None:
        src = _make_source(tmp_path)
        out = tmp_path / "backup.encbak"
        create_backup(src, out, "correct")
        with pytest.raises(InvalidTag):
            restore_backup(out, tmp_path / "restore", "wrong")

    def test_invalid_magic_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.encbak"
        bad.write_bytes(b"BADMAGIC" + b"\x00" * 100)
        with pytest.raises(ValueError, match="valid"):
            restore_backup(bad, tmp_path / "out", "pw")


class TestVerifyBackup:
    def test_verify_intact(self, tmp_path: Path) -> None:
        src = _make_source(tmp_path)
        out = tmp_path / "backup.encbak"
        create_backup(src, out, "password")
        assert verify_backup(out, "password") is True

    def test_verify_wrong_password_raises(self, tmp_path: Path) -> None:
        src = _make_source(tmp_path)
        out = tmp_path / "backup.encbak"
        create_backup(src, out, "correct")
        with pytest.raises(InvalidTag):
            verify_backup(out, "wrong")

    def test_verify_bad_magic_returns_false(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.encbak"
        bad.write_bytes(b"BADMAGIC" + b"\x00" * 100)
        assert verify_backup(bad, "pw") is False
