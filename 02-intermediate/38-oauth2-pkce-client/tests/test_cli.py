"""CLI tests for OAuth2 PKCE Client."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from project_38.cli import main
from project_38.core import TokenResponse


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


class TestChallengeCmd:
    def test_outputs_verifier_and_challenge(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["challenge"])
        assert result.exit_code == 0
        assert "Verifier" in result.output
        assert "Challenge" in result.output

    def test_json_output(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["challenge", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "code_verifier" in data
        assert "code_challenge" in data
        assert data["code_challenge_method"] == "S256"


class TestAuthUrlCmd:
    def test_builds_url(self, runner: CliRunner) -> None:
        result = runner.invoke(main, [
            "auth-url",
            "--endpoint", "https://auth.example.com/authorize",
            "--client-id", "testclient",
            "--redirect-uri", "http://localhost:8080/cb",
        ])
        assert result.exit_code == 0
        assert "https://auth.example.com/authorize" in result.output
        assert "code_challenge" in result.output

    def test_json_output(self, runner: CliRunner) -> None:
        result = runner.invoke(main, [
            "auth-url", "--json",
            "--endpoint", "https://auth.example.com/authorize",
            "--client-id", "testclient",
            "--redirect-uri", "http://localhost:8080/cb",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "url" in data
        assert "pkce" in data


class TestExchangeCmd:
    def test_state_mismatch_exits_2(self, runner: CliRunner) -> None:
        result = runner.invoke(main, [
            "exchange",
            "--token-endpoint", "https://auth.example.com/token",
            "--code", "abc",
            "--verifier", "verifier",
            "--client-id", "client",
            "--redirect-uri", "http://localhost/cb",
            "--state", "original_state",
            "--returned-state", "different_state",
        ])
        assert result.exit_code == 2

    def test_successful_exchange(self, runner: CliRunner) -> None:
        fake_response = TokenResponse(
            access_token="tok_xyz",
            token_type="Bearer",
            expires_in=3600,
            refresh_token=None,
            scope="openid",
            id_token=None,
            raw={},
        )
        with patch("project_38.cli.exchange_code_for_tokens", return_value=fake_response):
            result = runner.invoke(main, [
                "exchange",
                "--token-endpoint", "https://auth.example.com/token",
                "--code", "auth_code",
                "--verifier", "code_verifier",
                "--client-id", "client",
                "--redirect-uri", "http://localhost/cb",
            ])
        assert result.exit_code == 0
        assert "succeeded" in result.output
