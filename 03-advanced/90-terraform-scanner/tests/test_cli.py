"""Tests for project_90 CLI — Terraform Security Scanner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from project_90.cli import cli


DANGEROUS_TF = '''\
resource "aws_s3_bucket" "bad" {
  acl = "public-read"
}
resource "aws_security_group" "ssh_open" {
  ingress {
    from_port   = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''

CLEAN_TF = '''\
resource "aws_s3_bucket" "good" {
  bucket = "private"
  versioning {
    enabled = true
  }
}
'''


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def dangerous_tf(tmp_path: Path) -> Path:
    f = tmp_path / "bad.tf"
    f.write_text(DANGEROUS_TF)
    return f


@pytest.fixture()
def clean_tf(tmp_path: Path) -> Path:
    f = tmp_path / "clean.tf"
    f.write_text(CLEAN_TF)
    return f


class TestScanCommand:
    def test_scan_file_shows_findings(self, runner: CliRunner, dangerous_tf: Path) -> None:
        result = runner.invoke(cli, ["scan", str(dangerous_tf)])
        assert result.exit_code == 0
        assert "CRITICAL" in result.output or "HIGH" in result.output

    def test_scan_clean_file(self, runner: CliRunner, clean_tf: Path) -> None:
        result = runner.invoke(cli, ["scan", str(clean_tf)])
        assert result.exit_code == 0
        assert "Findings: 0" in result.output

    def test_scan_output_json(self, runner: CliRunner, dangerous_tf: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        result = runner.invoke(cli, ["scan", str(dangerous_tf), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "findings" in data

    def test_scan_exit_code_on_critical(self, runner: CliRunner, dangerous_tf: Path) -> None:
        result = runner.invoke(cli, ["scan", str(dangerous_tf), "--exit-code"])
        assert result.exit_code == 1

    def test_scan_no_exit_code_without_flag(self, runner: CliRunner, dangerous_tf: Path) -> None:
        result = runner.invoke(cli, ["scan", str(dangerous_tf)])
        assert result.exit_code == 0

    def test_scan_directory(self, runner: CliRunner, tmp_path: Path) -> None:
        (tmp_path / "main.tf").write_text(DANGEROUS_TF)
        result = runner.invoke(cli, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        assert ".tf file" in result.output

    def test_scan_missing_path(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["scan", "/nonexistent/path"])
        assert result.exit_code != 0

    def test_scan_min_severity_filters(self, runner: CliRunner, tmp_path: Path) -> None:
        tf = tmp_path / "rds.tf"
        tf.write_text('resource "aws_db_instance" "db" {\n  engine = "mysql"\n}\n')
        result = runner.invoke(cli, ["scan", str(tf), "--min-severity", "CRITICAL"])
        assert "TF-RDS-002" not in result.output


class TestVersionOption:
    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
