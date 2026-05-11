"""CLI tests for project_08."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from project_08.cli import main
from project_08.core import decrypt_file, encrypt_file

_PASSWORD = "test-passphrase-cli"


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    sys.argv = ["aes-crypt"] + args
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return int(exc.value.code or 0), captured.out, captured.err


class TestEncryptCLI:
    def test_encrypt_creates_enc_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        src = tmp_path / "plain.txt"
        src.write_bytes(b"hello world")
        out = tmp_path / "plain.txt.enc"
        with patch("project_08.cli.getpass.getpass", return_value=_PASSWORD):
            code, stdout, _ = _run(["encrypt", str(src), "--output", str(out)], capsys)
        assert code == 0
        assert out.exists()
        assert "Encrypted" in stdout

    def test_encrypt_missing_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with patch("project_08.cli.getpass.getpass", return_value=_PASSWORD):
            code, _, err = _run(["encrypt", str(tmp_path / "no.txt")], capsys)
        assert code == 1

    def test_password_mismatch_exits_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        src = tmp_path / "plain.txt"
        src.write_bytes(b"data")
        with patch(
            "project_08.cli.getpass.getpass", side_effect=["pass1", "pass2"]
        ):
            code, _, err = _run(["encrypt", str(src)], capsys)
        assert code == 1


class TestDecryptCLI:
    def test_decrypt_roundtrip(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        src = tmp_path / "plain.txt"
        src.write_bytes(b"secret content")
        enc = tmp_path / "plain.txt.enc"
        encrypt_file(src, enc, _PASSWORD)
        dec = tmp_path / "plain.txt.dec"
        with patch("project_08.cli.getpass.getpass", return_value=_PASSWORD):
            code, stdout, _ = _run(
                ["decrypt", str(enc), "--output", str(dec)], capsys
            )
        assert code == 0
        assert dec.read_bytes() == b"secret content"

    def test_wrong_password_exits_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        src = tmp_path / "plain.txt"
        src.write_bytes(b"data")
        enc = tmp_path / "plain.txt.enc"
        encrypt_file(src, enc, _PASSWORD)
        with patch("project_08.cli.getpass.getpass", return_value="wrongpass"):
            code, _, err = _run(["decrypt", str(enc)], capsys)
        assert code == 1
