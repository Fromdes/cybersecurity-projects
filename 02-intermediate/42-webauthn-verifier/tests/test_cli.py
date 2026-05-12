"""CLI tests for WebAuthn/FIDO2 Verifier."""

from __future__ import annotations

import base64
import json

import pytest
from click.testing import CliRunner

from project_42.cli import main
from project_42.core import build_sample_auth_data, FLAG_UP, FLAG_UV


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


class TestParseCmd:
    def test_parse_valid(self, runner: CliRunner) -> None:
        raw = build_sample_auth_data("example.com", sign_count=7)
        b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        result = runner.invoke(main, ["parse-authdata", b64])
        assert result.exit_code == 0
        assert "Sign Count" in result.output

    def test_parse_json(self, runner: CliRunner) -> None:
        raw = build_sample_auth_data("example.com", sign_count=3)
        b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        result = runner.invoke(main, ["parse-authdata", "--json", b64])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["sign_count"] == 3
        assert data["user_present"] is True


class TestDemoCmd:
    def test_demo_runs(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["demo"])
        assert result.exit_code == 0
        assert "Demo complete" in result.output
        assert "BLOCKED" in result.output  # replay should be blocked


class TestIssueChallengeCmd:
    def test_issue(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["issue-challenge"])
        assert result.exit_code == 0
        assert "Challenge" in result.output

    def test_issue_json(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["issue-challenge", "--json"])
        data = json.loads(result.output)
        assert "challenge" in data
        assert len(data["challenge"]) > 20
