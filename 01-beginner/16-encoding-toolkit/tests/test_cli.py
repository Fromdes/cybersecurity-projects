"""Tests for project_16.cli — Encoding Toolkit CLI."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from project_16.cli import main


def _run(argv: list[str], capsys: pytest.CaptureFixture) -> str:
    with patch("sys.argv", ["encode-toolkit", *argv]):
        main()
    return capsys.readouterr().out


class TestEncodeCommand:
    def test_base64_default(self, capsys: pytest.CaptureFixture) -> None:
        out = _run(["encode", "Hello"], capsys)
        assert "SGVsbG8=" in out

    def test_hex_encoding(self, capsys: pytest.CaptureFixture) -> None:
        out = _run(["encode", "AB", "--encoding", "hex"], capsys)
        assert "4142" in out

    def test_url_encoding(self, capsys: pytest.CaptureFixture) -> None:
        out = _run(["encode", "hello world", "--encoding", "url"], capsys)
        assert "hello%20world" in out


class TestDecodeCommand:
    def test_base64_decode(self, capsys: pytest.CaptureFixture) -> None:
        out = _run(["decode", "SGVsbG8=", "--encoding", "base64"], capsys)
        assert "Hello" in out

    def test_hex_decode(self, capsys: pytest.CaptureFixture) -> None:
        out = _run(["decode", "4142", "--encoding", "hex"], capsys)
        assert "AB" in out

    def test_invalid_hex_exits(self, capsys: pytest.CaptureFixture) -> None:
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["encode-toolkit", "decode", "ZZZ", "--encoding", "hex"]):
                main()
        assert exc_info.value.code == 1


class TestDetectCommand:
    def test_detects_hex(self, capsys: pytest.CaptureFixture) -> None:
        out = _run(["detect", "deadbeef"], capsys)
        assert "hex" in out.lower()

    def test_detects_no_match(self, capsys: pytest.CaptureFixture) -> None:
        out = _run(["detect", "plain text no encoding!@#"], capsys)
        assert "No common encoding" in out
