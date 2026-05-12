"""Tests for project_95 CLI — DLP Engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from project_95.cli import cli


SENSITIVE_TEXT = """\
Name: Alice Smith
Email: alice@example.com
SSN: 123-45-6789
Password: supersecret123
"""

CLEAN_TEXT = "This document contains no sensitive data.\n"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def sensitive_file(tmp_path: Path) -> Path:
    f = tmp_path / "data.txt"
    f.write_text(SENSITIVE_TEXT)
    return f


@pytest.fixture()
def clean_file(tmp_path: Path) -> Path:
    f = tmp_path / "clean.txt"
    f.write_text(CLEAN_TEXT)
    return f


class TestScanCommand:
    def test_scan_sensitive_file(self, runner: CliRunner, sensitive_file: Path) -> None:
        result = runner.invoke(cli, ["scan", str(sensitive_file), "--min-severity", "LOW"])
        assert result.exit_code == 0
        assert "Findings:" in result.output
        assert int(result.output.split("Findings:")[1].split()[0]) > 0

    def test_scan_clean_file(self, runner: CliRunner, clean_file: Path) -> None:
        result = runner.invoke(cli, ["scan", str(clean_file)])
        assert result.exit_code == 0
        assert "Findings: 0" in result.output

    def test_scan_output_json(self, runner: CliRunner, sensitive_file: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        result = runner.invoke(cli, ["scan", str(sensitive_file), "-o", str(out), "--min-severity", "LOW"])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "findings" in data

    def test_exit_code_on_critical(self, runner: CliRunner, sensitive_file: Path) -> None:
        result = runner.invoke(cli, ["scan", str(sensitive_file), "--exit-code", "--min-severity", "LOW"])
        assert result.exit_code == 1

    def test_no_exit_code_clean_file(self, runner: CliRunner, clean_file: Path) -> None:
        result = runner.invoke(cli, ["scan", str(clean_file), "--exit-code"])
        assert result.exit_code == 0

    def test_scan_directory(self, runner: CliRunner, tmp_path: Path) -> None:
        (tmp_path / "a.txt").write_text("aws_key = AKIAIOSFODNN7EXAMPLE\n")
        result = runner.invoke(cli, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        assert "file" in result.output.lower()

    def test_category_filter(self, runner: CliRunner, sensitive_file: Path) -> None:
        result = runner.invoke(cli, ["scan", str(sensitive_file), "--category", "credential", "--min-severity", "LOW"])
        assert result.exit_code == 0
        # Should only show credential findings, not email (PII)
        assert "DLP-003" not in result.output

    def test_missing_path_error(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["scan", "/nonexistent/path.txt"])
        assert result.exit_code != 0


class TestRedactCommand:
    def test_redact_outputs_to_stdout(self, runner: CliRunner, sensitive_file: Path) -> None:
        result = runner.invoke(cli, ["redact", str(sensitive_file)])
        assert result.exit_code == 0
        assert "alice@example.com" not in result.output
        assert "[REDACTED]" in result.output

    def test_redact_saves_to_file(self, runner: CliRunner, sensitive_file: Path, tmp_path: Path) -> None:
        out = tmp_path / "redacted.txt"
        result = runner.invoke(cli, ["redact", str(sensitive_file), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        redacted = out.read_text()
        assert "alice@example.com" not in redacted

    def test_redact_clean_file_unchanged(self, runner: CliRunner, clean_file: Path) -> None:
        result = runner.invoke(cli, ["redact", str(clean_file)])
        assert result.exit_code == 0
        assert CLEAN_TEXT.strip() in result.output


class TestVersionOption:
    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
