"""Tests for project 47 core module."""

from __future__ import annotations

import time

import pytest

from project_47.core import (
    FORM_FIELD_NAME,
    HEADER_NAME,
    CSRFService,
    TokenExpiredError,
    TokenInvalidError,
    TokenNotFoundError,
    extract_token,
)

SECRET = b"test-secret-key-32-bytes-padded!!"


@pytest.fixture()
def svc() -> CSRFService:
    return CSRFService(secret=SECRET, ttl=3600)


class TestGenerateToken:
    def test_returns_string(self, svc: CSRFService) -> None:
        token = svc.generate_token("session-1")
        assert isinstance(token, str)
        assert len(token) > 20

    def test_unique_per_call(self, svc: CSRFService) -> None:
        t1 = svc.generate_token("session-1")
        t2 = svc.generate_token("session-1")
        assert t1 != t2

    def test_different_sessions(self, svc: CSRFService) -> None:
        t1 = svc.generate_token("session-1")
        t2 = svc.generate_token("session-2")
        assert t1 != t2


class TestValidateToken:
    def test_valid_token(self, svc: CSRFService) -> None:
        sid = "session-valid"
        token = svc.generate_token(sid)
        svc.validate_token(sid, token)  # should not raise

    def test_wrong_token(self, svc: CSRFService) -> None:
        sid = "session-wrong"
        svc.generate_token(sid)
        with pytest.raises(TokenInvalidError):
            svc.validate_token(sid, "totally-wrong-token")

    def test_not_found(self, svc: CSRFService) -> None:
        with pytest.raises(TokenNotFoundError):
            svc.validate_token("ghost-session", "token")

    def test_expired_token(self) -> None:
        svc = CSRFService(secret=SECRET, ttl=0)
        sid = "session-exp"
        token = svc.generate_token(sid)
        time.sleep(0.01)
        with pytest.raises(TokenExpiredError):
            svc.validate_token(sid, token)

    def test_cross_session_replay(self, svc: CSRFService) -> None:
        t1 = svc.generate_token("session-a")
        svc.generate_token("session-b")
        with pytest.raises(TokenInvalidError):
            svc.validate_token("session-b", t1)


class TestRotateToken:
    def test_old_token_invalid(self, svc: CSRFService) -> None:
        sid = "session-rotate"
        old = svc.generate_token(sid)
        svc.rotate_token(sid)
        # After rotation a new entry exists; old token no longer matches → InvalidError
        with pytest.raises(TokenInvalidError):
            svc.validate_token(sid, old)

    def test_new_token_valid(self, svc: CSRFService) -> None:
        sid = "session-rotate2"
        svc.generate_token(sid)
        new_token = svc.rotate_token(sid)
        svc.validate_token(sid, new_token)


class TestPurgeExpired:
    def test_purge_removes_expired(self) -> None:
        svc = CSRFService(secret=SECRET, ttl=0)
        svc.generate_token("s1")
        svc.generate_token("s2")
        time.sleep(0.01)
        removed = svc.purge_expired()
        assert removed == 2


class TestExtractToken:
    def test_prefers_header_by_default(self) -> None:
        headers = {HEADER_NAME: "header-token"}
        form = {FORM_FIELD_NAME: "form-token"}
        assert extract_token(headers, form) == "header-token"

    def test_falls_back_to_form(self) -> None:
        headers: dict[str, str] = {}
        form = {FORM_FIELD_NAME: "form-token"}
        assert extract_token(headers, form) == "form-token"

    def test_prefers_form_when_flag_set(self) -> None:
        headers = {HEADER_NAME: "header-token"}
        form = {FORM_FIELD_NAME: "form-token"}
        assert extract_token(headers, form, prefer_header=False) == "form-token"

    def test_returns_none_when_absent(self) -> None:
        assert extract_token({}, {}) is None
