"""CLI tests for project_07."""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from project_07.cli import main

_SHA1_OF_PASSWORD = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
_SUFFIX = _SHA1_OF_PASSWORD[5:]


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    sys.argv = ["hibp-check", *args]
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return int(exc.value.code or 0), captured.out, captured.err


class TestCLIPassword:
    def test_pwned_exits_1(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("project_07.cli.check_password", return_value=5_000_000):
            code, out, _ = _run(["password", "password"], capsys)
        assert code == 1
        assert "PWNED" in out

    def test_safe_exits_0(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("project_07.cli.check_password", return_value=0):
            code, out, _ = _run(["password", "SafeP@ss!"], capsys)
        assert code == 0
        assert "SAFE" in out

    def test_stdin_flag(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import io
        monkeypatch.setattr("sys.stdin", io.StringIO("somepassword\n"))
        with patch("project_07.cli.check_password", return_value=0):
            code, _out, _ = _run(["password", "--stdin"], capsys)
        assert code == 0


class TestCLIHash:
    def test_hash_pwned(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("project_07.cli.check_hash", return_value=100):
            code, out, _ = _run(["hash", _SHA1_OF_PASSWORD], capsys)
        assert code == 1
        assert "PWNED" in out

    def test_invalid_hash(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, _, _err = _run(["hash", "notvalid"], capsys)
        assert code == 1

    def test_network_timeout(self, capsys: pytest.CaptureFixture[str]) -> None:
        import requests as req
        with patch("project_07.cli.check_password", side_effect=req.Timeout):
            code, _, _err = _run(["password", "test"], capsys)
        assert code == 2
