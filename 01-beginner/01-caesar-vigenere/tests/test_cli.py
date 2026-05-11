"""CLI tests for project_01."""

from __future__ import annotations

import sys

import pytest

from project_01.cli import main


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[str, str]:
    """Run CLI with *args* and return (stdout, stderr)."""
    sys.argv = ["cipher-toolkit"] + args
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    captured = capsys.readouterr()
    return captured.out, captured.err


class TestCaesarCLI:
    """Tests for the caesar subcommand."""

    def test_encrypt(self, capsys: pytest.CaptureFixture[str]) -> None:
        out, _ = _run(["caesar", "ABC", "--shift", "3", "--encrypt"], capsys)
        assert "DEF" in out

    def test_decrypt(self, capsys: pytest.CaptureFixture[str]) -> None:
        out, _ = _run(["caesar", "DEF", "--shift", "3", "--decrypt"], capsys)
        assert "ABC" in out

    def test_crack(self, capsys: pytest.CaptureFixture[str]) -> None:
        out, _ = _run(
            ["caesar", "Wkh txlfn eurzq ira", "--crack"],
            capsys,
        )
        assert "shift=" in out


class TestVigenereCLI:
    """Tests for the vigenere subcommand."""

    def test_encrypt(self, capsys: pytest.CaptureFixture[str]) -> None:
        out, _ = _run(["vigenere", "HELLO", "--key", "KEY", "--encrypt"], capsys)
        assert out.strip()

    def test_hint(self, capsys: pytest.CaptureFixture[str]) -> None:
        out, _ = _run(["vigenere", "ABCDEF" * 10, "--hint"], capsys)
        assert "IoC=" in out

    def test_missing_key_returns_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        sys.argv = ["cipher-toolkit", "vigenere", "HELLO", "--encrypt"]
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1


class TestFreqCLI:
    """Tests for the freq subcommand."""

    def test_plain_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        out, _ = _run(["freq", "AABBC"], capsys)
        assert "A:" in out

    def test_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        import json
        out, _ = _run(["freq", "Hello", "--json"], capsys)
        data = json.loads(out)
        assert "H" in data
