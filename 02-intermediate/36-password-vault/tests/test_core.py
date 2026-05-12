"""Tests for project_36.core — Personal Password Vault."""
from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from project_36.core import Vault, VaultEntry, derive_key, generate_password


class TestGeneratePassword:
    def test_length(self) -> None:
        pwd = generate_password(24)
        assert len(pwd) == 24

    def test_default_length(self) -> None:
        pwd = generate_password()
        assert len(pwd) == 24

    def test_uniqueness(self) -> None:
        assert generate_password() != generate_password()

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 8"):
            generate_password(4)


class TestDeriveKey:
    def test_length(self) -> None:
        assert len(derive_key("pw", b"0123456789abcdef")) == 32

    def test_deterministic(self) -> None:
        s = b"0123456789abcdef"
        assert derive_key("pw", s) == derive_key("pw", s)


class TestVaultEntry:
    def test_new_has_uuid(self) -> None:
        e = VaultEntry.new("github.com", "user", "pass")
        assert len(e.id) == 36

    def test_new_timestamps(self) -> None:
        e = VaultEntry.new("site", "user", "pass")
        assert e.created_at == e.modified_at


class TestVault:
    def test_add_and_get(self, tmp_path: Path) -> None:
        v = Vault(tmp_path / "vault.enc", "master")
        entry = v.add("github.com", "alice", "secret")
        got = v.get(entry.id)
        assert got.site == "github.com"
        assert got.password == "secret"

    def test_persist_and_reload(self, tmp_path: Path) -> None:
        path = tmp_path / "vault.enc"
        v1 = Vault(path, "master")
        e = v1.add("site.com", "bob", "pass")
        v2 = Vault(path, "master")
        assert v2.get(e.id).username == "bob"

    def test_wrong_password_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "vault.enc"
        v = Vault(path, "correct")
        v.add("x", "y", "z")
        with pytest.raises(InvalidTag):
            Vault(path, "wrong")

    def test_search_by_site(self, tmp_path: Path) -> None:
        v = Vault(tmp_path / "vault.enc", "master")
        v.add("github.com", "alice", "p1")
        v.add("gitlab.com", "alice", "p2")
        v.add("amazon.com", "alice", "p3")
        results = v.search("git")
        assert len(results) == 2

    def test_search_by_username(self, tmp_path: Path) -> None:
        v = Vault(tmp_path / "vault.enc", "master")
        v.add("a.com", "alice@example.com", "p1")
        v.add("b.com", "bob@example.com", "p2")
        results = v.search("alice")
        assert len(results) == 1

    def test_delete(self, tmp_path: Path) -> None:
        v = Vault(tmp_path / "vault.enc", "master")
        e = v.add("x", "y", "z")
        v.delete(e.id)
        assert len(v.list_all()) == 0

    def test_delete_nonexistent_raises(self, tmp_path: Path) -> None:
        v = Vault(tmp_path / "vault.enc", "master")
        with pytest.raises(KeyError):
            v.delete("fake-id")

    def test_get_nonexistent_raises(self, tmp_path: Path) -> None:
        v = Vault(tmp_path / "vault.enc", "master")
        with pytest.raises(KeyError):
            v.get("nonexistent")

    def test_update(self, tmp_path: Path) -> None:
        v = Vault(tmp_path / "vault.enc", "master")
        e = v.add("site.com", "user", "old")
        updated = v.update(e.id, password="new")
        assert updated.password == "new"
        assert updated.username == "user"

    def test_empty_site_raises(self, tmp_path: Path) -> None:
        v = Vault(tmp_path / "vault.enc", "master")
        with pytest.raises(ValueError, match="site"):
            v.add("", "user", "pass")

    def test_empty_username_raises(self, tmp_path: Path) -> None:
        v = Vault(tmp_path / "vault.enc", "master")
        with pytest.raises(ValueError, match="username"):
            v.add("site.com", "", "pass")

    def test_empty_master_password_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="master_password"):
            Vault(tmp_path / "vault.enc", "")

    def test_file_mode_600(self, tmp_path: Path) -> None:
        path = tmp_path / "vault.enc"
        v = Vault(path, "master")
        v.add("x", "y", "z")
        assert (path.stat().st_mode & 0o777) == 0o600
