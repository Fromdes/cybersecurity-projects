"""CLI tests for project_14."""

from __future__ import annotations

import sys

import pytest

from project_14.cli import main
from project_14.core import HashAlgorithm, hash_password

_PASSWORD = "test-password-123"


def _run(
    args: list[str],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    stdin_text: str = "",
) -> tuple[int, str, str]:
    sys.argv = ["passwd-hash"] + args
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(stdin_text))
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return int(exc.value.code or 0), captured.out, captured.err


class TestHashCLI:
    def test_argon2id_hash(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        code, out, _ = _run(["--stdin", "hash"], capsys, monkeypatch, _PASSWORD)
        assert code == 0
        assert out.strip().startswith("$argon2id$")

    def test_pbkdf2_hash(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        code, out, _ = _run(
            ["--stdin", "--algorithm", "pbkdf2", "hash"], capsys, monkeypatch, _PASSWORD
        )
        assert code == 0
        assert ":" in out.strip()

    def test_empty_password_exits_1(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        code, _, err = _run(["--stdin", "hash"], capsys, monkeypatch, "")
        assert code == 1


class TestVerifyCLI:
    def test_valid_argon2id(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        encoded = hash_password(_PASSWORD, algorithm=HashAlgorithm.ARGON2ID).encoded
        code, out, _ = _run(["--stdin", "verify", encoded], capsys, monkeypatch, _PASSWORD)
        assert code == 0
        assert "VALID" in out

    def test_invalid_argon2id(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        encoded = hash_password(_PASSWORD, algorithm=HashAlgorithm.ARGON2ID).encoded
        code, _, _ = _run(["--stdin", "verify", encoded], capsys, monkeypatch, "wrongpass")
        assert code == 1


class TestCheckRehashCLI:
    def test_current_params_ok(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        encoded = hash_password(_PASSWORD, algorithm=HashAlgorithm.ARGON2ID).encoded
        code, out, _ = _run(["check-rehash", encoded], capsys, monkeypatch)
        assert code == 0
        assert "OK" in out
