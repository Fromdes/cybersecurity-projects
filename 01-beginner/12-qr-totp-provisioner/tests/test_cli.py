"""CLI tests for project_12."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from project_12.cli import main

_SECRET = "JBSWY3DPEHPK3PXP"


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    sys.argv = ["totp-qr", *args]
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return int(exc.value.code or 0), captured.out, captured.err


class TestUriMode:
    def test_prints_otpauth(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["--secret", _SECRET, "--uri"], capsys)
        assert code == 0
        assert "otpauth://" in out

    def test_custom_issuer(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(
            ["--secret", _SECRET, "--issuer", "CoolApp", "--uri"], capsys
        )
        assert code == 0
        assert "CoolApp" in out


class TestTerminalMode:
    def test_prints_qr(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["--secret", _SECRET, "--terminal"], capsys)
        assert code == 0
        assert len(out.splitlines()) > 10


class TestPngMode:
    def test_creates_png(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path
    ) -> None:
        out_file = tmp_path / "qr.png"
        code, out, _ = _run(
            ["--secret", _SECRET, "--png", str(out_file)], capsys
        )
        assert code == 0
        assert out_file.exists()
        assert "QR code saved" in out
