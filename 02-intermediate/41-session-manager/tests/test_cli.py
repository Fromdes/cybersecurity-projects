"""CLI tests for Session Manager."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from project_41.cli import main


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


class TestCreateCmd:
    def test_create_outputs_session_id(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["create", "--user", "alice"])
        assert result.exit_code == 0
        assert "Session ID" in result.output

    def test_create_json(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["create", "--user", "bob", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "session_id" in data
        assert "csrf_token" in data
        assert data["user_id"] == "bob"


class TestDemoCmd:
    def test_demo_runs(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["demo"])
        assert result.exit_code == 0
        assert "Demo complete" in result.output
        assert "CSRF match: True" in result.output
