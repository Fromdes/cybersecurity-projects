"""CLI tests for JWT Validator."""

from __future__ import annotations

import time

import jwt
import pytest
from click.testing import CliRunner

from project_37.cli import main

SECRET = "supersecretkey_for_testing_only_32b"


def _tok(payload: dict) -> str:
    return jwt.encode(payload, SECRET, algorithm="HS256")


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


class TestInspectCmd:
    def test_inspect_valid(self, runner: CliRunner) -> None:
        now = int(time.time())
        token = _tok({"sub": "alice", "exp": now + 3600, "iat": now, "iss": "test"})
        result = runner.invoke(main, ["inspect", token])
        assert result.exit_code == 0
        assert "alice" in result.output

    def test_inspect_json(self, runner: CliRunner) -> None:
        token = _tok({"sub": "bob"})
        result = runner.invoke(main, ["inspect", "--json", token])
        assert result.exit_code == 0
        assert '"status"' in result.output

    def test_inspect_malformed(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["inspect", "not-a-jwt"])
        assert "MALFORMED" in result.output


class TestValidateCmd:
    def test_validate_success(self, runner: CliRunner) -> None:
        now = int(time.time())
        token = _tok({"sub": "u1", "exp": now + 3600, "iat": now})
        result = runner.invoke(main, ["validate", token, "--key", SECRET, "--alg", "HS256"])
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_validate_wrong_key(self, runner: CliRunner) -> None:
        token = _tok({"sub": "u1", "exp": int(time.time()) + 3600})
        result = runner.invoke(main, ["validate", token, "--key", "badkey", "--alg", "HS256"])
        assert result.exit_code == 1
        assert "INVALID_SIGNATURE" in result.output

    def test_validate_expired(self, runner: CliRunner) -> None:
        token = _tok({"sub": "u1", "exp": int(time.time()) - 10})
        result = runner.invoke(main, ["validate", token, "--key", SECRET, "--alg", "HS256"])
        assert result.exit_code == 1
        assert "EXPIRED" in result.output
