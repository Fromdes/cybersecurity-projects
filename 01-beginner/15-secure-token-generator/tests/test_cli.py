"""Tests for project_15.cli — Secure Token Generator CLI."""
from __future__ import annotations

import re
from unittest.mock import patch

import pytest

from project_15.cli import main


def _run(argv: list[str], capsys: pytest.CaptureFixture) -> str:
    with patch("sys.argv", ["sectoken", *argv]):
        main()
    return capsys.readouterr().out


class TestGenerateCommand:
    def test_default_hex_output(self, capsys: pytest.CaptureFixture) -> None:
        out = _run(["generate"], capsys)
        assert re.search(r"[0-9a-f]{64}", out)

    def test_hex_format_explicit(self, capsys: pytest.CaptureFixture) -> None:
        out = _run(["generate", "--format", "hex"], capsys)
        assert "hex" in out

    def test_base64url_format(self, capsys: pytest.CaptureFixture) -> None:
        out = _run(["generate", "--format", "base64url"], capsys)
        assert "base64url" in out

    def test_uuid4_format(self, capsys: pytest.CaptureFixture) -> None:
        out = _run(["generate", "--format", "uuid4"], capsys)
        assert re.search(r"[0-9a-f-]{36}", out)

    def test_quiet_flag(self, capsys: pytest.CaptureFixture) -> None:
        out = _run(["generate", "--quiet"], capsys)
        assert "[" not in out  # no metadata
        assert len(out.strip()) == 64  # 32-byte hex

    def test_count_flag(self, capsys: pytest.CaptureFixture) -> None:
        out = _run(["generate", "--count", "3"], capsys)
        assert len(out.strip().splitlines()) == 3

    def test_invalid_byte_length_exits(self, capsys: pytest.CaptureFixture) -> None:
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["sectoken", "generate", "--bytes", "1"]):
                main()
        assert exc_info.value.code == 1


class TestEntropyCommand:
    def test_entropy_output(self, capsys: pytest.CaptureFixture) -> None:
        out = _run(["entropy", "64"], capsys)
        assert "256.0 bits" in out
        assert "STRONG" in out

    def test_weak_entropy(self, capsys: pytest.CaptureFixture) -> None:
        out = _run(["entropy", "8", "--charset", "2"], capsys)
        assert "WEAK" in out
