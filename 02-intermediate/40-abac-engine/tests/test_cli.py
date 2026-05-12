"""CLI tests for ABAC Policy Engine."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from project_40.cli import main

POLICY_YAML = """
combining_algorithm: deny-overrides
rules:
  - name: deny-external-sensitive
    effect: deny
    priority: 100
    conditions:
      - attribute: subject.location
        operator: eq
        value: external
      - attribute: resource.classification
        operator: eq
        value: sensitive
  - name: permit-admin
    effect: permit
    priority: 50
    conditions:
      - attribute: subject.role
        operator: eq
        value: admin
"""


@pytest.fixture()
def policy_file(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(POLICY_YAML)
    return str(p)


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


class TestEvaluateCmd:
    def test_permit_admin(self, runner: CliRunner, policy_file: str) -> None:
        result = runner.invoke(main, [
            "evaluate", "--policy", policy_file,
            "-s", "role=admin", "-s", "location=internal",
            "-r", "classification=public",
        ])
        assert result.exit_code == 0
        assert "PERMIT" in result.output

    def test_deny_external_sensitive(self, runner: CliRunner, policy_file: str) -> None:
        result = runner.invoke(main, [
            "evaluate", "--policy", policy_file,
            "-s", "location=external",
            "-r", "classification=sensitive",
        ])
        assert result.exit_code == 1
        assert "DENY" in result.output

    def test_json_output(self, runner: CliRunner, policy_file: str) -> None:
        result = runner.invoke(main, [
            "evaluate", "--json", "--policy", policy_file,
            "-s", "role=admin",
            "-r", "name=dashboard",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["allowed"] is True

    def test_no_match_denied(self, runner: CliRunner, policy_file: str) -> None:
        result = runner.invoke(main, [
            "evaluate", "--policy", policy_file,
            "-s", "location=unknown",
            "-r", "name=file",
        ])
        assert result.exit_code == 1


class TestDumpCmd:
    def test_dump_output(self, runner: CliRunner, policy_file: str) -> None:
        result = runner.invoke(main, ["dump", "--policy", policy_file])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "rules" in data
        assert "combining_algorithm" in data


class TestInitPolicyCmd:
    def test_creates_file(self, runner: CliRunner, tmp_path) -> None:
        out = str(tmp_path / "out.yaml")
        result = runner.invoke(main, ["init-policy", "--output", out])
        assert result.exit_code == 0
        assert "written" in result.output
