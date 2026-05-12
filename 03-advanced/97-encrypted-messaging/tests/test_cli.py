"""Tests for project_97 CLI — Encrypted Messaging."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from project_97.cli import cli


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


class TestDemoCommand:
    def test_demo_runs(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["demo", "--messages", "3"])
        assert result.exit_code == 0
        assert "OK" in result.output

    def test_demo_shows_message_count(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["demo", "--messages", "2"])
        assert result.exit_code == 0
        assert "4 messages" in result.output


class TestRatchetCommand:
    def test_replay_rejected(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["test-ratchet"])
        assert result.exit_code == 0
        assert "OK" in result.output


class TestVersionOption:
    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
