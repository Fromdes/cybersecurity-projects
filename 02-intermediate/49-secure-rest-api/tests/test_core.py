"""Tests for project 49 core module."""

from __future__ import annotations

import time

import pytest

from project_49.core import (
    APIKeyStore,
    RateLimiter,
    get_security_headers,
    sign_request,
    verify_request_signature,
)

SECRET = b"test-secret-key"


class TestAPIKeyStore:
    def test_create_and_validate(self) -> None:
        store = APIKeyStore()
        key = store.create_key("alice", ["read", "write"])
        meta = store.validate_key(key)
        assert meta["owner"] == "alice"

    def test_invalid_key_raises(self) -> None:
        store = APIKeyStore()
        with pytest.raises(ValueError, match="Invalid"):
            store.validate_key("bad-key")

    def test_scope_check(self) -> None:
        store = APIKeyStore()
        key = store.create_key("bob", ["read"])
        with pytest.raises(ValueError, match="Scope"):
            store.validate_key(key, required_scope="write")

    def test_revoke(self) -> None:
        store = APIKeyStore()
        key = store.create_key("carol", ["read"])
        assert store.revoke_key(key) is True
        with pytest.raises(ValueError, match="revoked"):
            store.validate_key(key)

    def test_revoke_nonexistent(self) -> None:
        store = APIKeyStore()
        assert store.revoke_key("nonexistent") is False


class TestRateLimiter:
    def test_allows_within_limit(self) -> None:
        rl = RateLimiter(window=60, max_requests=5)
        for _ in range(5):
            assert rl.is_allowed("user-1") is True

    def test_blocks_over_limit(self) -> None:
        rl = RateLimiter(window=60, max_requests=3)
        for _ in range(3):
            rl.is_allowed("user-2")
        assert rl.is_allowed("user-2") is False

    def test_remaining_decrements(self) -> None:
        rl = RateLimiter(window=60, max_requests=10)
        rl.is_allowed("user-3")
        assert rl.remaining("user-3") == 9

    def test_different_identifiers_independent(self) -> None:
        rl = RateLimiter(window=60, max_requests=2)
        rl.is_allowed("a")
        rl.is_allowed("a")
        assert rl.is_allowed("b") is True


class TestSecurityHeaders:
    def test_contains_required_headers(self) -> None:
        headers = get_security_headers()
        assert "X-Content-Type-Options" in headers
        assert "Strict-Transport-Security" in headers
        assert "X-Frame-Options" in headers

    def test_extra_headers_merged(self) -> None:
        headers = get_security_headers({"X-Custom": "value"})
        assert headers["X-Custom"] == "value"


class TestRequestSigning:
    def test_sign_and_verify(self) -> None:
        ts = str(time.time())
        body = b'{"hello": "world"}'
        sig = sign_request("POST", "/api/data", body, ts, SECRET)
        verify_request_signature("POST", "/api/data", body, ts, sig, SECRET)

    def test_wrong_signature_fails(self) -> None:
        ts = str(time.time())
        with pytest.raises(ValueError, match="signature"):
            verify_request_signature("GET", "/", b"", ts, "bad-sig", SECRET)

    def test_expired_timestamp_fails(self) -> None:
        old_ts = str(time.time() - 400)
        body = b""
        sig = sign_request("GET", "/", body, old_ts, SECRET)
        with pytest.raises(ValueError, match="old"):
            verify_request_signature("GET", "/", body, old_ts, sig, SECRET, max_age_seconds=300)

    def test_invalid_timestamp_format(self) -> None:
        with pytest.raises(ValueError, match="timestamp"):
            verify_request_signature("GET", "/", b"", "not-a-number", "sig", SECRET)
