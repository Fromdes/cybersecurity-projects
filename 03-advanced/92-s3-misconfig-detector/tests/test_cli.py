"""Tests for project_92 CLI — S3 Misconfiguration Detector."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from project_92.cli import cli


PUBLIC_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Sid": "PublicRead", "Principal": "*",
         "Action": "s3:GetObject", "Resource": "arn:aws:s3:::public-bucket/*"},
    ],
}

CLEAN_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Sid": "AppRead", "Principal": {"AWS": "arn:aws:iam::123:role/app"},
         "Action": "s3:GetObject", "Resource": "arn:aws:s3:::private-bucket/*"},
    ],
}


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def public_policy_file(tmp_path: Path) -> Path:
    f = tmp_path / "public-bucket.json"
    f.write_text(json.dumps(PUBLIC_POLICY))
    return f


@pytest.fixture()
def clean_policy_file(tmp_path: Path) -> Path:
    f = tmp_path / "private-bucket.json"
    f.write_text(json.dumps(CLEAN_POLICY))
    return f


class TestCheckCommand:
    def test_check_public_bucket_shows_findings(self, runner: CliRunner, public_policy_file: Path) -> None:
        result = runner.invoke(cli, ["check", str(public_policy_file)])
        assert result.exit_code == 0
        assert "CRITICAL" in result.output

    def test_check_clean_bucket_zero_findings(self, runner: CliRunner, clean_policy_file: Path) -> None:
        result = runner.invoke(cli, ["check", str(clean_policy_file)])
        assert result.exit_code == 0
        assert "Findings: 0" in result.output

    def test_check_output_json(self, runner: CliRunner, public_policy_file: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        result = runner.invoke(cli, ["check", str(public_policy_file), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "findings" in data

    def test_exit_code_on_critical(self, runner: CliRunner, public_policy_file: Path) -> None:
        result = runner.invoke(cli, ["check", str(public_policy_file), "--exit-code"])
        assert result.exit_code == 1

    def test_no_exit_code_without_flag(self, runner: CliRunner, public_policy_file: Path) -> None:
        result = runner.invoke(cli, ["check", str(public_policy_file)])
        assert result.exit_code == 0

    def test_bucket_name_override(self, runner: CliRunner, public_policy_file: Path) -> None:
        result = runner.invoke(cli, ["check", str(public_policy_file), "--bucket-name", "my-override"])
        assert result.exit_code == 0
        assert "my-override" in result.output

    def test_missing_file_error(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["check", "/nonexistent/policy.json"])
        assert result.exit_code != 0


class TestVersionOption:
    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
