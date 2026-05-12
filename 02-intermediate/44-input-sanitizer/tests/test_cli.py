"""CLI tests for Input Sanitization Library."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from project_44.cli import main


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


class TestScanCmd:
    def test_scan_xss(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["scan", "<script>alert(1)</script>"])
        assert result.exit_code == 1
        assert "xss" in result.output.lower()

    def test_scan_clean(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["scan", "Hello world"])
        assert result.exit_code == 0
        assert "CLEAN" in result.output

    def test_scan_json(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["scan", "--json", "'; DROP TABLE users--"])
        data = json.loads(result.output)
        assert data["clean"] is False
        assert len(data["threats"]) > 0


class TestSanitizeCmd:
    def test_sanitize_strips_html(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["sanitize", "<b>bold</b>text"])
        assert "<b>" not in result.output

    def test_sanitize_json(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["sanitize", "--json", "safe text"])
        data = json.loads(result.output)
        assert data["sanitized"] == "safe text"
        assert data["clean"] is True


class TestFilenameCmd:
    def test_traversal(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["filename", "../../etc/passwd"])
        assert result.exit_code == 0
        assert "Modified : True" in result.output

    def test_safe_name(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["filename", "report.pdf"])
        assert "Modified : False" in result.output


class TestEmailCmd:
    def test_valid_email(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["validate-email", "user@example.com"])
        assert result.exit_code == 0
        assert "True" in result.output

    def test_invalid_email(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["validate-email", "notanemail"])
        assert result.exit_code == 1


class TestDemoCmd:
    def test_demo_runs(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["demo"])
        assert result.exit_code == 0
        assert "THREAT" in result.output
        assert "CLEAN" in result.output
