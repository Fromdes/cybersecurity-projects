"""Tests for Real-Time FIM CLI."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from project_78.cli import cli


class TestBaselineCommand:
    def test_build_baseline(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("hello")
        out = tmp_path / "baseline.json"
        runner = CliRunner()
        result = runner.invoke(cli, ["baseline", str(f), "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        assert "1 file" in result.output


class TestVerifyCommand:
    def test_verify_no_changes(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("hello")
        out = tmp_path / "baseline.json"
        runner = CliRunner()
        runner.invoke(cli, ["baseline", str(f), "--output", str(out)])
        result = runner.invoke(cli, ["verify", str(out)])
        assert result.exit_code == 0
        assert "No deviations" in result.output

    def test_verify_detects_modification(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("original")
        out = tmp_path / "baseline.json"
        runner = CliRunner()
        runner.invoke(cli, ["baseline", str(f), "--output", str(out)])
        f.write_text("modified!")
        result = runner.invoke(cli, ["verify", str(out)])
        assert result.exit_code == 0
        assert "MODIFIED" in result.output

    def test_verify_detects_deletion(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("content")
        out = tmp_path / "baseline.json"
        runner = CliRunner()
        runner.invoke(cli, ["baseline", str(f), "--output", str(out)])
        f.unlink()
        result = runner.invoke(cli, ["verify", str(out)])
        assert result.exit_code == 0
        assert "DELETED" in result.output
