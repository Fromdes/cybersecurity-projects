"""Tests for project_91 CLI — Cloud IAM Policy Analyzer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from project_91.cli import cli

ADMIN_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Sid": "Admin", "Action": "*", "Resource": "*"}],
}

CLEAN_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Sid": "ReadOnly", "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::my-bucket/key"},
    ],
}

LOGGING_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Sid": "DisableLogs", "Action": "cloudtrail:StopLogging",
         "Resource": "*"},
    ],
}


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def admin_policy_file(tmp_path: Path) -> Path:
    f = tmp_path / "admin.json"
    f.write_text(json.dumps(ADMIN_POLICY))
    return f


@pytest.fixture()
def clean_policy_file(tmp_path: Path) -> Path:
    f = tmp_path / "clean.json"
    f.write_text(json.dumps(CLEAN_POLICY))
    return f


@pytest.fixture()
def logging_policy_file(tmp_path: Path) -> Path:
    f = tmp_path / "logging.json"
    f.write_text(json.dumps(LOGGING_POLICY))
    return f


class TestAnalyzeCommand:
    def test_analyze_admin_policy_shows_findings(self, runner: CliRunner, admin_policy_file: Path) -> None:
        result = runner.invoke(cli, ["analyze", str(admin_policy_file)])
        assert result.exit_code == 0
        assert "CRITICAL" in result.output

    def test_analyze_clean_policy_zero_findings(self, runner: CliRunner, clean_policy_file: Path) -> None:
        result = runner.invoke(cli, ["analyze", str(clean_policy_file)])
        assert result.exit_code == 0
        assert "Findings: 0" in result.output

    def test_analyze_output_json(self, runner: CliRunner, admin_policy_file: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        result = runner.invoke(cli, ["analyze", str(admin_policy_file), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "findings" in data

    def test_exit_code_on_critical(self, runner: CliRunner, admin_policy_file: Path) -> None:
        result = runner.invoke(cli, ["analyze", str(admin_policy_file), "--exit-code"])
        assert result.exit_code == 1

    def test_no_exit_code_without_flag(self, runner: CliRunner, admin_policy_file: Path) -> None:
        result = runner.invoke(cli, ["analyze", str(admin_policy_file)])
        assert result.exit_code == 0

    def test_min_severity_filters(self, runner: CliRunner, logging_policy_file: Path) -> None:
        result = runner.invoke(cli, ["analyze", str(logging_policy_file), "--min-severity", "CRITICAL"])
        assert result.exit_code == 0
        assert "IAM-006" not in result.output

    def test_missing_file_error(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["analyze", "/nonexistent/policy.json"])
        assert result.exit_code != 0


class TestVersionOption:
    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
