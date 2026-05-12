"""Tests for project_35.cli — Encrypted Backup Tool CLI."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from project_35.cli import main


def _make_source(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "data.txt").write_text("backup me")
    return src


class TestCLI:
    def test_create_command(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        src = _make_source(tmp_path)
        out = tmp_path / "backup.encbak"
        with patch("sys.argv", ["enc-backup", "create", str(src), str(out)]):
            with patch("getpass.getpass", return_value="password"):
                main()
        captured = capsys.readouterr()
        assert "created" in captured.out.lower()
        assert out.exists()

    def test_password_mismatch_exits(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        src = _make_source(tmp_path)
        out = tmp_path / "backup.encbak"
        passwords = iter(["password", "different"])
        with patch("sys.argv", ["enc-backup", "create", str(src), str(out)]):
            with patch("getpass.getpass", side_effect=passwords):
                with pytest.raises(SystemExit) as exc_info:
                    main()
        assert exc_info.value.code == 1

    def test_restore_command(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        src = _make_source(tmp_path)
        out = tmp_path / "backup.encbak"
        with patch("sys.argv", ["enc-backup", "create", str(src), str(out)]):
            with patch("getpass.getpass", return_value="pw"):
                main()
        restore_dir = tmp_path / "restored"
        with patch("sys.argv", ["enc-backup", "restore", str(out), str(restore_dir)]):
            with patch("getpass.getpass", return_value="pw"):
                main()
        captured = capsys.readouterr()
        assert "Restored" in captured.out

    def test_verify_ok(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        src = _make_source(tmp_path)
        out = tmp_path / "backup.encbak"
        with patch("sys.argv", ["enc-backup", "create", str(src), str(out)]):
            with patch("getpass.getpass", return_value="pw"):
                main()
        with patch("sys.argv", ["enc-backup", "verify", str(out)]):
            with patch("getpass.getpass", return_value="pw"):
                main()
        captured = capsys.readouterr()
        assert "OK" in captured.out

    def test_missing_source_exits(self, tmp_path: Path) -> None:
        with patch("sys.argv", ["enc-backup", "create",
                                str(tmp_path / "nope"), str(tmp_path / "out.encbak")]):
            with patch("getpass.getpass", return_value="pw"):
                with pytest.raises(SystemExit) as exc_info:
                    main()
        assert exc_info.value.code == 1
