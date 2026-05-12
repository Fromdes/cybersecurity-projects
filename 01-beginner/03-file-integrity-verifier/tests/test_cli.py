"""CLI tests for project_03."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from project_03.cli import main


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    sys.argv = ["fim", *args]
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return int(exc.value.code or 0), captured.out, captured.err


@pytest.fixture()
def sample_dir(tmp_path: Path) -> Path:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    (monitored / "a.txt").write_bytes(b"hello")
    (monitored / "b.txt").write_bytes(b"world")
    return monitored


class TestInitCLI:
    def test_init_creates_baseline(
        self, sample_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        output = tmp_path / "baseline.json"
        code, out, _ = _run(["init", str(sample_dir), "--output", str(output)], capsys)
        assert code == 0
        assert output.exists()
        assert "Baseline created" in out

    def test_init_non_directory(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, _, _err = _run(["init", str(tmp_path / "no_dir")], capsys)
        assert code == 1


class TestCheckCLI:
    def test_check_clean(
        self, sample_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bl = tmp_path / "baseline.json"
        _run(["init", str(sample_dir), "--output", str(bl)], capsys)
        code, out, _ = _run(["check", str(sample_dir), "--baseline", str(bl)], capsys)
        assert code == 0
        assert "CLEAN" in out

    def test_check_modified(
        self, sample_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bl = tmp_path / "baseline.json"
        _run(["init", str(sample_dir), "--output", str(bl)], capsys)
        (sample_dir / "a.txt").write_bytes(b"tampered")
        code, out, _ = _run(["check", str(sample_dir), "--baseline", str(bl)], capsys)
        assert code == 2
        assert "CHANGED" in out

    def test_check_json_output(
        self, sample_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bl = tmp_path / "baseline.json"
        _run(["init", str(sample_dir), "--output", str(bl)], capsys)
        code, out, _ = _run(
            ["check", str(sample_dir), "--baseline", str(bl), "--json"], capsys
        )
        assert code == 0
        data = json.loads(out)
        assert "clean" in data

    def test_check_missing_baseline(
        self, sample_dir: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, _, _err = _run(
            ["check", str(sample_dir), "--baseline", str(sample_dir / "no.json")],
            capsys,
        )
        assert code == 1
