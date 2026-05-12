"""CLI tests for Rate Limiter."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from project_43.cli import main


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


class TestDemoCmd:
    def test_token_bucket_demo(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["demo", "--algo", "token-bucket", "--requests", "6", "--limit", "3"])
        assert result.exit_code == 0
        assert "ALLOW" in result.output
        assert "DENY" in result.output

    def test_sliding_window_demo(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["demo", "--algo", "sliding-window", "--requests", "6", "--limit", "3"])
        assert result.exit_code == 0

    def test_fixed_window_demo(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["demo", "--algo", "fixed-window", "--requests", "6", "--limit", "3"])
        assert result.exit_code == 0


class TestCheckCmd:
    def test_check_allows(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["check", "--key", "alice", "--limit", "10", "--window", "60"])
        assert result.exit_code == 0
        assert "ALLOWED" in result.output

    def test_check_json(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["check", "--key", "alice", "--json", "--limit", "10"])
        data = json.loads(result.output)
        assert data["allowed"] is True
        assert "remaining" in data


class TestCompareCmd:
    def test_compare_runs(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["compare", "--limit", "3", "--requests", "5"])
        assert result.exit_code == 0
