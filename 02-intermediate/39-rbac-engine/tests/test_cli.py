"""CLI tests for RBAC Engine."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from project_39.cli import main

POLICY_YAML = """
roles:
  viewer:
    permissions:
      - reports:read
    parents: []
  admin:
    permissions:
      - "*:*"
    parents:
      - viewer
users:
  alice:
    roles:
      - admin
  carol:
    roles:
      - viewer
"""


@pytest.fixture()
def policy_file(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(POLICY_YAML)
    return str(p)


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


class TestCheckCmd:
    def test_allow(self, runner: CliRunner, policy_file: str) -> None:
        result = runner.invoke(main, ["check", "--policy", policy_file, "--user", "alice", "--resource", "anything", "--action", "do"])
        assert result.exit_code == 0
        assert "ALLOW" in result.output

    def test_deny(self, runner: CliRunner, policy_file: str) -> None:
        result = runner.invoke(main, ["check", "--policy", policy_file, "--user", "carol", "--resource", "reports", "--action", "write"])
        assert result.exit_code == 1
        assert "DENY" in result.output

    def test_json_output(self, runner: CliRunner, policy_file: str) -> None:
        result = runner.invoke(main, ["check", "--json", "--policy", policy_file, "--user", "alice", "--resource", "r", "--action", "a"])
        data = json.loads(result.output)
        assert data["allowed"] is True


class TestListPermissionsCmd:
    def test_list_permissions(self, runner: CliRunner, policy_file: str) -> None:
        result = runner.invoke(main, ["list-permissions", "--policy", policy_file, "--user", "carol"])
        assert result.exit_code == 0
        assert "reports:read" in result.output

    def test_unknown_user(self, runner: CliRunner, policy_file: str) -> None:
        result = runner.invoke(main, ["list-permissions", "--policy", policy_file, "--user", "unknown"])
        assert result.exit_code == 1


class TestDumpCmd:
    def test_dump(self, runner: CliRunner, policy_file: str) -> None:
        result = runner.invoke(main, ["dump", "--policy", policy_file])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "roles" in data
        assert "users" in data


class TestInitPolicyCmd:
    def test_creates_file(self, runner: CliRunner, tmp_path) -> None:
        out = str(tmp_path / "out.yaml")
        result = runner.invoke(main, ["init-policy", "--output", out])
        assert result.exit_code == 0
        assert "written" in result.output
