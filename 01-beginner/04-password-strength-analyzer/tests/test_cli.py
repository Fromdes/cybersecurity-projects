"""CLI tests for project_04."""

from __future__ import annotations

import json
import sys

import pytest

from project_04.cli import main


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    sys.argv = ["password-analyze"] + args
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return int(exc.value.code or 0), captured.out, captured.err


class TestCLI:
    def test_weak_password_exits_1(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["abc"], capsys)
        assert code == 1

    def test_strong_password_exits_0(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["C0rrectH0rseB@tteryStaple!"], capsys)
        assert code == 0

    def test_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["Abc1!xyz89", "--json"], capsys)
        data = json.loads(out)
        assert "score" in data
        assert "entropy_bits" in data
        assert "warnings" in data

    def test_no_color_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        _, out, _ = _run(["SomePassword1!", "--no-color"], capsys)
        assert "\033[" not in out

    def test_text_output_contains_strength(self, capsys: pytest.CaptureFixture[str]) -> None:
        _, out, _ = _run(["SomePassword1!extra", "--no-color"], capsys)
        assert "Strength" in out

    def test_stdin_flag(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import io
        monkeypatch.setattr("sys.stdin", io.StringIO("C0rrectH0rse@Staple!\n"))
        code, out, _ = _run(["--stdin"], capsys)
        assert "Strength" in out
