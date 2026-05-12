"""CLI tests for project_11."""

from __future__ import annotations

import sys

import pytest

from project_11.cli import main
from project_11.core import TOTPConfig, generate_hotp, generate_totp

_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    sys.argv = ["otp"] + args
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return int(exc.value.code or 0), captured.out, captured.err


class TestGenerateSecretCLI:
    def test_outputs_base32(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["generate-secret"], capsys)
        assert code == 0
        assert out.strip().isalnum()


class TestTOTPCLI:
    def test_generate(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["totp", "--secret", _SECRET, "--generate"], capsys)
        assert code == 0
        assert out.strip().isdigit()

    def test_verify_valid(self, capsys: pytest.CaptureFixture[str]) -> None:
        import time
        cfg = TOTPConfig(secret=_SECRET)
        otp = generate_totp(cfg, at=time.time())
        code, out, _ = _run(
            ["totp", "--secret", _SECRET, "--verify", otp], capsys
        )
        assert code == 0
        assert "VALID" in out

    def test_verify_invalid(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, _, err = _run(
            ["totp", "--secret", _SECRET, "--verify", "000000"], capsys
        )
        assert code == 1

    def test_uri_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(
            ["totp", "--secret", _SECRET, "--generate", "--uri"], capsys
        )
        assert code == 0
        assert "otpauth://" in out


class TestHOTPCLI:
    def test_generate(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(
            ["hotp", "--secret", _SECRET, "--counter", "0", "--generate"], capsys
        )
        assert code == 0
        assert out.strip().isdigit()

    def test_verify_valid(self, capsys: pytest.CaptureFixture[str]) -> None:
        otp = generate_hotp(_SECRET, 7)
        code, out, _ = _run(
            ["hotp", "--secret", _SECRET, "--counter", "7", "--verify", otp], capsys
        )
        assert code == 0
        assert "VALID" in out
