"""Tests for project_36.cli — Personal Password Vault CLI."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from project_36.cli import main


class TestCLI:
    def _run(self, args: list[str], vault_path: Path, password: str = "master") -> None:
        with patch("sys.argv", ["vault", "--vault", str(vault_path), *args]):
            with patch("getpass.getpass", return_value=password):
                main()

    def test_add_and_list(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        vault = tmp_path / "vault.enc"
        self._run(["add", "github.com", "alice", "--password", "secret"], vault)
        self._run(["list"], vault)
        captured = capsys.readouterr()
        assert "github.com" in captured.out

    def test_add_generate(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        vault = tmp_path / "vault.enc"
        self._run(["add", "site.com", "bob", "--generate"], vault)
        captured = capsys.readouterr()
        assert "Generated password" in captured.out

    def test_get_shows_password(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        vault = tmp_path / "vault.enc"
        self._run(["add", "site.com", "alice", "--password", "hunter2"], vault)
        from project_36.core import Vault
        with patch("getpass.getpass", return_value="master"):
            v = Vault(vault, "master")
        entry_id = v.list_all()[0].id
        self._run(["get", entry_id], vault)
        captured = capsys.readouterr()
        assert "hunter2" in captured.out

    def test_list_search(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        vault = tmp_path / "vault.enc"
        self._run(["add", "github.com", "alice", "--password", "p1"], vault)
        self._run(["add", "amazon.com", "alice", "--password", "p2"], vault)
        self._run(["list", "--search", "github"], vault)
        captured = capsys.readouterr()
        assert "github.com" in captured.out
        assert "amazon.com" not in captured.out

    def test_delete(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        vault = tmp_path / "vault.enc"
        self._run(["add", "x.com", "user", "--password", "pw"], vault)
        from project_36.core import Vault
        with patch("getpass.getpass", return_value="master"):
            v = Vault(vault, "master")
        entry_id = v.list_all()[0].id
        self._run(["delete", entry_id], vault)
        captured = capsys.readouterr()
        assert "deleted" in captured.out

    def test_generate_command(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("sys.argv", ["vault", "--vault", str(tmp_path / "v.enc"), "generate"]):
            with patch("getpass.getpass", return_value="master"):
                main()
        captured = capsys.readouterr()
        assert len(captured.out.strip()) >= 24

    def test_wrong_master_exits(self, tmp_path: Path) -> None:
        vault = tmp_path / "vault.enc"
        self._run(["add", "x.com", "u", "--password", "pw"], vault, "correct")
        with patch("sys.argv", ["vault", "--vault", str(vault), "list"]):
            with patch("getpass.getpass", return_value="wrong"):
                with pytest.raises(SystemExit) as exc_info:
                    main()
        assert exc_info.value.code == 1
