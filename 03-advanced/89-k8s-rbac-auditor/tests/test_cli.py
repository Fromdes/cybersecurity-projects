"""Tests for project_89 CLI — Kubernetes RBAC Auditor."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from project_89.cli import cli


DANGEROUS_YAML = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dangerous-role
rules:
  - resources: ["*"]
    verbs: ["*"]
"""

CLEAN_YAML = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: reader
rules:
  - resources: ["configmaps"]
    verbs: ["get", "list"]
"""

SECRET_YAML = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
  - resources: ["secrets"]
    verbs: ["get", "list", "watch"]
"""


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def dangerous_yaml(tmp_path: Path) -> Path:
    f = tmp_path / "dangerous.yaml"
    f.write_text(DANGEROUS_YAML)
    return f


@pytest.fixture()
def clean_yaml(tmp_path: Path) -> Path:
    f = tmp_path / "clean.yaml"
    f.write_text(CLEAN_YAML)
    return f


@pytest.fixture()
def secret_yaml(tmp_path: Path) -> Path:
    f = tmp_path / "secret.yaml"
    f.write_text(SECRET_YAML)
    return f


class TestAuditCommand:
    def test_audit_dangerous_role_shows_findings(self, runner: CliRunner, dangerous_yaml: Path) -> None:
        result = runner.invoke(cli, ["audit", str(dangerous_yaml)])
        assert result.exit_code == 0
        assert "CRITICAL" in result.output or "HIGH" in result.output

    def test_audit_clean_role_shows_zero_findings(self, runner: CliRunner, clean_yaml: Path) -> None:
        result = runner.invoke(cli, ["audit", str(clean_yaml)])
        assert result.exit_code == 0
        assert "Findings: 0" in result.output

    def test_audit_output_json(self, runner: CliRunner, dangerous_yaml: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        result = runner.invoke(cli, ["audit", str(dangerous_yaml), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "findings" in data
        assert "total_findings" in data

    def test_audit_exit_code_on_critical(self, runner: CliRunner, dangerous_yaml: Path) -> None:
        result = runner.invoke(cli, ["audit", str(dangerous_yaml), "--exit-code"])
        assert result.exit_code == 1

    def test_audit_no_exit_code_without_flag(self, runner: CliRunner, dangerous_yaml: Path) -> None:
        result = runner.invoke(cli, ["audit", str(dangerous_yaml)])
        assert result.exit_code == 0

    def test_audit_min_severity_filters_low(self, runner: CliRunner, secret_yaml: Path) -> None:
        result = runner.invoke(cli, ["audit", str(secret_yaml), "--min-severity", "CRITICAL"])
        assert result.exit_code == 0
        assert "RBAC-004" not in result.output

    def test_audit_min_severity_medium_shows_high(self, runner: CliRunner, secret_yaml: Path) -> None:
        result = runner.invoke(cli, ["audit", str(secret_yaml), "--min-severity", "MEDIUM"])
        assert result.exit_code == 0
        assert "RBAC-004" in result.output

    def test_audit_missing_file_error(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["audit", "/nonexistent/path.yaml"])
        assert result.exit_code != 0

    def test_audit_resources_audited_count(self, runner: CliRunner, dangerous_yaml: Path) -> None:
        result = runner.invoke(cli, ["audit", str(dangerous_yaml)])
        assert "1 RBAC resource" in result.output


class TestVersionOption:
    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
