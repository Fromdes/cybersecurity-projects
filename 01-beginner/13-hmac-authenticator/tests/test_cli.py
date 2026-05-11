"""CLI tests for project_13."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from project_13.cli import main
from project_13.core import compute_hmac, derive_key_from_passphrase

_PASSPHRASE = "test-key-for-cli"
_MSG = "hello world"


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    sys.argv = ["hmac-auth"] + args
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return int(exc.value.code or 0), captured.out, captured.err


class TestSignCLI:
    def test_outputs_hex(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["--key", _PASSPHRASE, "sign", _MSG], capsys)
        assert code == 0
        assert len(out.strip()) == 64

    def test_sha512_outputs_128_chars(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(
            ["--key", _PASSPHRASE, "--algorithm", "sha512", "sign", _MSG], capsys
        )
        assert code == 0
        assert len(out.strip()) == 128


class TestVerifyCLI:
    def test_valid_prints_valid(self, capsys: pytest.CaptureFixture[str]) -> None:
        key = derive_key_from_passphrase(_PASSPHRASE)
        digest = compute_hmac(_MSG.encode(), key).digest
        code, out, _ = _run(
            ["--key", _PASSPHRASE, "verify", _MSG, digest], capsys
        )
        assert code == 0
        assert "VALID" in out

    def test_invalid_exits_1(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, _, err = _run(
            ["--key", _PASSPHRASE, "verify", _MSG, "deadbeef" * 8], capsys
        )
        assert code == 1


class TestSignFileCLI:
    def test_outputs_hex(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path
    ) -> None:
        f = tmp_path / "data.txt"
        f.write_text("file content")
        code, out, _ = _run(
            ["--key", _PASSPHRASE, "sign-file", str(f)], capsys
        )
        assert code == 0
        assert len(out.strip()) == 64

    def test_missing_file_exits_2(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path
    ) -> None:
        code, _, _ = _run(
            ["--key", _PASSPHRASE, "sign-file", str(tmp_path / "nope.txt")], capsys
        )
        assert code == 2


class TestVerifyFileCLI:
    def test_valid_file(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path
    ) -> None:
        f = tmp_path / "data.txt"
        f.write_text("file content")
        key = derive_key_from_passphrase(_PASSPHRASE)
        from project_13.core import sign_file
        digest = sign_file(f, key).digest
        code, out, _ = _run(
            ["--key", _PASSPHRASE, "verify-file", str(f), digest], capsys
        )
        assert code == 0
        assert "VALID" in out
