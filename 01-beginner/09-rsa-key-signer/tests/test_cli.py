"""CLI tests for project_09."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from project_09.cli import main
from project_09.core import generate_key_pair, save_private_key, save_public_key, sign_file

_PASSWORD = "cli-test-password"


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    sys.argv = ["rsa-sign", *args]
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return int(exc.value.code or 0), captured.out, captured.err


@pytest.fixture()
def keys(tmp_path: Path) -> tuple[Path, Path]:
    private_key, public_key = generate_key_pair()
    priv_path = tmp_path / "private.pem"
    pub_path = tmp_path / "public.pem"
    save_private_key(private_key, priv_path, _PASSWORD)
    save_public_key(public_key, pub_path)
    return priv_path, pub_path


class TestGenerateCLI:
    def test_generate_creates_key_files(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        priv = tmp_path / "priv.pem"
        pub = tmp_path / "pub.pem"
        with patch(
            "project_09.cli.getpass.getpass", side_effect=[_PASSWORD, _PASSWORD]
        ):
            code, _out, _ = _run(
                ["generate-key", "--private", str(priv), "--public", str(pub)], capsys
            )
        assert code == 0
        assert priv.exists()
        assert pub.exists()

    def test_password_mismatch_exits_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with patch(
            "project_09.cli.getpass.getpass", side_effect=["pass1", "pass2"]
        ):
            code, _, _ = _run(["generate-key"], capsys)
        assert code == 1


class TestSignCLI:
    def test_sign_creates_sig_file(
        self,
        tmp_path: Path,
        keys: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        f = tmp_path / "doc.txt"
        f.write_bytes(b"document")
        sig = tmp_path / "doc.txt.sig"
        with patch("project_09.cli.getpass.getpass", return_value=_PASSWORD):
            code, _out, _ = _run(
                ["sign", str(f), "--key", str(keys[0]), "--output", str(sig)],
                capsys,
            )
        assert code == 0
        assert sig.exists()


class TestVerifyCLI:
    def test_verify_valid(
        self,
        tmp_path: Path,
        keys: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from project_09.core import load_private_key
        f = tmp_path / "doc.txt"
        f.write_bytes(b"verified content")
        private_key = load_private_key(keys[0], _PASSWORD)
        sig_bytes = sign_file(f, private_key)
        sig = tmp_path / "doc.txt.sig"
        sig.write_bytes(sig_bytes)
        code, out, _ = _run(
            ["verify", str(f), "--key", str(keys[1]), "--signature", str(sig)],
            capsys,
        )
        assert code == 0
        assert "VALID" in out

    def test_verify_tampered(
        self,
        tmp_path: Path,
        keys: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from project_09.core import load_private_key
        f = tmp_path / "doc.txt"
        f.write_bytes(b"original")
        private_key = load_private_key(keys[0], _PASSWORD)
        sig_bytes = sign_file(f, private_key)
        sig = tmp_path / "doc.txt.sig"
        sig.write_bytes(sig_bytes)
        f.write_bytes(b"tampered!")
        code, _, err = _run(
            ["verify", str(f), "--key", str(keys[1]), "--signature", str(sig)],
            capsys,
        )
        assert code == 2
        assert "INVALID" in err
