"""Tests for project_93 CLI — Zero Trust Network Gateway."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from project_93.cli import cli

ALLOW_POLICY = {
    "default_action": "DENY",
    "rules": [
        {
            "rule_id": "R001",
            "description": "Allow internal HTTPS",
            "principals": ["*"],
            "source_cidrs": ["10.0.0.0/8"],
            "destinations": ["*.internal"],
            "ports": [443],
            "protocols": ["tcp"],
            "action": "ALLOW",
            "require_mfa": False,
            "max_risk_score": 100,
        }
    ],
}

MFA_POLICY = {
    "default_action": "DENY",
    "rules": [
        {
            "rule_id": "R001",
            "description": "Allow with MFA",
            "principals": ["*"],
            "source_cidrs": ["*"],
            "destinations": ["*"],
            "ports": [],
            "protocols": ["tcp"],
            "action": "ALLOW",
            "require_mfa": True,
            "max_risk_score": 100,
        }
    ],
}


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def allow_policy_file(tmp_path: Path) -> Path:
    f = tmp_path / "allow.json"
    f.write_text(json.dumps(ALLOW_POLICY))
    return f


@pytest.fixture()
def mfa_policy_file(tmp_path: Path) -> Path:
    f = tmp_path / "mfa.json"
    f.write_text(json.dumps(MFA_POLICY))
    return f


@pytest.fixture()
def requests_file(tmp_path: Path) -> Path:
    lines = [
        json.dumps({"request_id": "r1", "principal": "alice", "source_ip": "10.0.0.5",
                    "destination": "app.internal", "port": 443, "protocol": "tcp"}),
        json.dumps({"request_id": "r2", "principal": "bob", "source_ip": "192.168.1.10",
                    "destination": "db.internal", "port": 3306, "protocol": "tcp"}),
    ]
    f = tmp_path / "requests.jsonl"
    f.write_text("\n".join(lines))
    return f


class TestCheckCommand:
    def test_allowed_request(self, runner: CliRunner, allow_policy_file: Path) -> None:
        result = runner.invoke(cli, [
            "check", "--policy", str(allow_policy_file),
            "--principal", "alice", "--source-ip", "10.0.0.1",
            "--destination", "app.internal", "--port", "443",
        ])
        assert result.exit_code == 0
        assert "ALLOW" in result.output

    def test_denied_request(self, runner: CliRunner, allow_policy_file: Path) -> None:
        result = runner.invoke(cli, [
            "check", "--policy", str(allow_policy_file),
            "--principal", "alice", "--source-ip", "8.8.8.8",
            "--destination", "app.internal", "--port", "443",
        ])
        assert result.exit_code == 1
        assert "DENY" in result.output

    def test_mfa_required_denied_without_mfa(self, runner: CliRunner, mfa_policy_file: Path) -> None:
        result = runner.invoke(cli, [
            "check", "--policy", str(mfa_policy_file),
            "--principal", "alice", "--source-ip", "10.0.0.1",
            "--destination", "app.internal", "--port", "443",
        ])
        assert result.exit_code == 1

    def test_mfa_required_allowed_with_mfa(self, runner: CliRunner, mfa_policy_file: Path) -> None:
        result = runner.invoke(cli, [
            "check", "--policy", str(mfa_policy_file),
            "--principal", "alice", "--source-ip", "10.0.0.1",
            "--destination", "app.internal", "--port", "443", "--mfa",
        ])
        assert result.exit_code == 0


class TestEvaluateCommand:
    def test_evaluate_requests_file(self, runner: CliRunner, allow_policy_file: Path, requests_file: Path) -> None:
        result = runner.invoke(cli, [
            "evaluate", "--policy", str(allow_policy_file), "--requests", str(requests_file),
        ])
        assert result.exit_code == 0
        assert "allowed" in result.output
        assert "denied" in result.output

    def test_evaluate_saves_audit_log(self, runner: CliRunner, allow_policy_file: Path,
                                       requests_file: Path, tmp_path: Path) -> None:
        out = tmp_path / "audit.jsonl"
        result = runner.invoke(cli, [
            "evaluate", "--policy", str(allow_policy_file),
            "--requests", str(requests_file), "--output", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()
        lines = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        assert len(lines) == 2


class TestVersionOption:
    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
