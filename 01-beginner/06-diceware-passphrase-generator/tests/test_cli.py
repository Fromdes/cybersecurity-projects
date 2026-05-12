"""CLI tests for project_06."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from project_06.cli import main


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    sys.argv = ["diceware", *args]
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return int(exc.value.code or 0), captured.out, captured.err


class TestDicewareCLI:
    def test_default_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run([], capsys)
        assert code == 0
        assert "-" in out  # default separator

    def test_word_count(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["--words", "4"], capsys)
        assert code == 0
        assert len(out.strip().split("-")) == 4

    def test_count_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["--count", "3"], capsys)
        assert code == 0
        assert len(out.strip().splitlines()) == 3

    def test_entropy_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["--entropy"], capsys)
        assert code == 0
        assert "bits" in out

    def test_custom_separator(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["--separator", " "], capsys)
        assert code == 0
        assert " " in out.strip()

    def test_missing_wordlist_file(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, _, _err = _run(["--wordlist", "/no/such/file.txt"], capsys)
        assert code == 1

    def test_custom_wordlist(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        wl = tmp_path / "words.txt"
        wl.write_text("\n".join(f"word{i}" for i in range(200)), encoding="utf-8")
        code, out, _ = _run(["--wordlist", str(wl), "--words", "4"], capsys)
        assert code == 0
        assert len(out.strip().split("-")) == 4
