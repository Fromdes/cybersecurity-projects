"""Tests for Forensics Timeline Builder CLI."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from project_81.cli import cli


class TestBuildCommand:
    def test_build_from_filesystem(self, tmp_path: Path) -> None:
        f = tmp_path / "sample.txt"
        f.write_text("hello world")
        out = tmp_path / "timeline.jsonl"
        runner = CliRunner()
        result = runner.invoke(cli, ["build", "--fs", str(f), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    def test_build_from_generic_log(self, tmp_path: Path) -> None:
        log = tmp_path / "app.log"
        log.write_text("2024-05-12T10:00:00Z INFO started\n")
        out = tmp_path / "timeline.jsonl"
        runner = CliRunner()
        result = runner.invoke(cli, ["build", "--log", str(log), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()

    def test_build_csv_format(self, tmp_path: Path) -> None:
        f = tmp_path / "sample.txt"
        f.write_text("content")
        out = tmp_path / "timeline.csv"
        runner = CliRunner()
        result = runner.invoke(cli, ["build", "--fs", str(f), "-o", str(out), "--format", "csv"])
        assert result.exit_code == 0
        assert out.exists()


class TestSummaryCommand:
    def test_summary(self, tmp_path: Path) -> None:
        from datetime import datetime, timezone
        timeline_file = tmp_path / "timeline.jsonl"
        events = [
            {"timestamp": "2024-05-12T10:00:00+00:00", "source": "filesystem",
             "event_type": "FILE_MODIFIED", "description": "test", "artifact": "/f", "details": {}},
        ]
        timeline_file.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["summary", str(timeline_file)])
        assert result.exit_code == 0
        assert "total" in result.output
