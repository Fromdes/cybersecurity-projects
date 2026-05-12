"""CLI tests for project_05."""

from __future__ import annotations

import sys

import pytest

from project_05.cli import main


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    sys.argv = ["password-gen"] + args
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return int(exc.value.code or 0), captured.out, captured.err


class TestCLI:
    def test_default_generates_one_password(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run([], capsys)
        assert code == 0
        lines = [l for l in out.strip().splitlines() if l]
        assert len(lines) == 1

    def test_count_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["--count", "5"], capsys)
        assert code == 0
        lines = [l for l in out.strip().splitlines() if l]
        assert len(lines) == 5

    def test_length_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["--length", "24"], capsys)
        assert code == 0
        pw = out.strip()
        assert len(pw) == 24

    def test_entropy_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["--entropy"], capsys)
        assert code == 0
        assert "bits" in out

    def test_invalid_length_exits_1(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, _, err = _run(["--length", "3"], capsys)
        assert code == 1

    def test_no_special_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        from project_05.core import CHARS_SPECIAL
        code, out, _ = _run(["--no-special", "--length", "50", "--count", "5"], capsys)
        assert code == 0
        for pw in out.strip().splitlines():
            assert all(c not in CHARS_SPECIAL for c in pw.split()[0])
