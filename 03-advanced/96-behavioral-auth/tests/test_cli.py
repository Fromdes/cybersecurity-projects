"""Tests for project_96 CLI — Behavioral Authentication."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from project_96.cli import cli


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


class TestEnrollCommand:
    def test_enroll_generates_profile(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(cli, ["enroll", "--user", "alice", "--profile-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / "alice.profile.json").exists()

    def test_enroll_output_mentions_user(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(cli, ["enroll", "--user", "bob", "--profile-dir", str(tmp_path)])
        assert "bob" in result.output


class TestVerifyCommand:
    def test_verify_after_enroll(self, runner: CliRunner, tmp_path: Path) -> None:
        runner.invoke(cli, ["enroll", "--user", "alice", "--profile-dir", str(tmp_path)])
        result = runner.invoke(cli, ["verify", "--user", "alice", "--profile-dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "alice" in result.output

    def test_verify_missing_profile_exits_2(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(cli, ["verify", "--user", "ghost", "--profile-dir", str(tmp_path)])
        assert result.exit_code == 2


class TestDemoCommand:
    def test_demo_runs_without_error(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["demo"])
        assert result.exit_code == 0
        assert "ACCEPTED" in result.output or "REJECTED" in result.output


class TestVersionOption:
    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
