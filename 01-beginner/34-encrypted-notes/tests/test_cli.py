"""Tests for project_34.cli — Encrypted Notes CLI."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from project_34.cli import main


class TestCLI:
    def _run(self, args: list[str], store_path: Path, password: str = "secret") -> None:
        with patch("sys.argv", ["enc-notes", "--store", str(store_path)] + args):
            with patch("getpass.getpass", return_value=password):
                main()

    def test_add_and_list(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        store = tmp_path / "notes.enc"
        self._run(["add", "MyNote", "body text"], store)
        self._run(["list"], store)
        captured = capsys.readouterr()
        assert "MyNote" in captured.out

    def test_get_note(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        store = tmp_path / "notes.enc"
        self._run(["add", "GetNote", "secret body"], store)
        from project_34.core import NotesStore
        with patch("getpass.getpass", return_value="secret"):
            ns = NotesStore(store, "secret")
        note_id = ns.list_notes()[0].id
        self._run(["get", note_id], store)
        captured = capsys.readouterr()
        assert "secret body" in captured.out

    def test_delete_note(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        store = tmp_path / "notes.enc"
        self._run(["add", "ToDelete", ""], store)
        from project_34.core import NotesStore
        with patch("getpass.getpass", return_value="secret"):
            ns = NotesStore(store, "secret")
        note_id = ns.list_notes()[0].id
        self._run(["delete", note_id], store)
        captured = capsys.readouterr()
        assert "deleted" in captured.out

    def test_list_empty(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        store = tmp_path / "notes.enc"
        self._run(["list"], store)
        captured = capsys.readouterr()
        assert "No notes" in captured.out

    def test_wrong_password_exits(self, tmp_path: Path) -> None:
        store = tmp_path / "notes.enc"
        self._run(["add", "x", "y"], store, password="correct")
        with patch("sys.argv", ["enc-notes", "--store", str(store), "list"]):
            with patch("getpass.getpass", return_value="wrong"):
                with pytest.raises(SystemExit) as exc_info:
                    main()
        assert exc_info.value.code == 1
