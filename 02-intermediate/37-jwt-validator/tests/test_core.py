"""Tests for JWT Validator core logic."""

from __future__ import annotations

import time

import jwt
import pytest

from project_37.core import (
    ValidationStatus,
    decode_header_unsafe,
    decode_payload_unsafe,
    inspect_token,
    validate_token,
)

SECRET = "supersecretkey_for_testing_only_32b"
ALGORITHMS_HS = ["HS256"]
ALGORITHMS_RS = ["RS256"]


def _make_token(payload: dict, secret: str = SECRET, algorithm: str = "HS256") -> str:
    return jwt.encode(payload, secret, algorithm=algorithm)


class TestDecodeUnsafe:
    def test_decode_header(self) -> None:
        token = _make_token({"sub": "u1"})
        header = decode_header_unsafe(token)
        assert header["alg"] == "HS256"

    def test_decode_payload(self) -> None:
        token = _make_token({"sub": "alice", "iss": "test"})
        payload = decode_payload_unsafe(token)
        assert payload["sub"] == "alice"
        assert payload["iss"] == "test"

    def test_malformed_raises(self) -> None:
        with pytest.raises(ValueError):
            decode_header_unsafe("not.a.valid.jwt.extra")

    def test_malformed_two_parts(self) -> None:
        with pytest.raises(ValueError):
            decode_payload_unsafe("onlytwoparts.here")


class TestInspectToken:
    def test_valid_token_inspected(self) -> None:
        now = int(time.time())
        token = _make_token({"sub": "u1", "iss": "test", "iat": now, "exp": now + 3600})
        result = inspect_token(token)
        assert result.header is not None
        assert result.claims is not None
        assert result.claims.subject == "u1"
        assert result.fingerprint is not None

    def test_expired_token_warns(self) -> None:
        token = _make_token({"exp": int(time.time()) - 100, "sub": "u1"})
        result = inspect_token(token)
        assert any("expired" in w.lower() for w in result.warnings)

    def test_missing_recommended_claims_warns(self) -> None:
        token = _make_token({"custom": "value"})
        result = inspect_token(token)
        warnings_text = " ".join(result.warnings)
        assert "exp" in warnings_text or "iss" in warnings_text

    def test_malformed_returns_malformed_status(self) -> None:
        result = inspect_token("garbage.token.data")
        assert result.status == ValidationStatus.MALFORMED

    def test_symmetric_alg_warns(self) -> None:
        token = _make_token({"sub": "u1"})
        result = inspect_token(token)
        assert any("HS256" in w or "Symmetric" in w or "symmetric" in w for w in result.warnings)


class TestValidateToken:
    def test_valid_hmac(self) -> None:
        now = int(time.time())
        token = _make_token({"sub": "u1", "iat": now, "exp": now + 3600})
        result = validate_token(token, SECRET, algorithms=ALGORITHMS_HS)
        assert result.is_valid
        assert result.status == ValidationStatus.VALID

    def test_expired_returns_expired(self) -> None:
        token = _make_token({"sub": "u1", "exp": int(time.time()) - 60})
        result = validate_token(token, SECRET, algorithms=ALGORITHMS_HS)
        assert result.status == ValidationStatus.EXPIRED
        assert not result.is_valid

    def test_wrong_secret_invalid_signature(self) -> None:
        token = _make_token({"sub": "u1", "exp": int(time.time()) + 3600})
        result = validate_token(token, "wrongsecret", algorithms=ALGORITHMS_HS)
        assert result.status == ValidationStatus.INVALID_SIGNATURE

    def test_none_algorithm_rejected(self) -> None:
        # Craft a token with alg=none by hand
        import base64, json
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "evil"}).encode()).rstrip(b"=").decode()
        fake_token = f"{header}.{payload}."
        result = validate_token(fake_token, SECRET, algorithms=ALGORITHMS_HS)
        assert result.status in (ValidationStatus.DANGEROUS_ALGORITHM, ValidationStatus.MALFORMED, ValidationStatus.INVALID_SIGNATURE)
        assert not result.is_valid

    def test_issuer_mismatch(self) -> None:
        now = int(time.time())
        token = _make_token({"sub": "u1", "iss": "wrong-issuer", "exp": now + 3600, "iat": now})
        result = validate_token(token, SECRET, algorithms=ALGORITHMS_HS, expected_issuer="correct-issuer")
        assert result.status == ValidationStatus.ISSUER_MISMATCH

    def test_audience_mismatch(self) -> None:
        now = int(time.time())
        token = _make_token({"sub": "u1", "aud": "other", "exp": now + 3600, "iat": now})
        result = validate_token(token, SECRET, algorithms=ALGORITHMS_HS, expected_audience="myapp")
        assert result.status == ValidationStatus.AUDIENCE_MISMATCH

    def test_required_claim_missing(self) -> None:
        now = int(time.time())
        token = _make_token({"sub": "u1", "exp": now + 3600})
        result = validate_token(token, SECRET, algorithms=ALGORITHMS_HS, required_claims=["role"])
        assert result.status == ValidationStatus.MISSING_CLAIM

    def test_token_too_old(self) -> None:
        old_iat = int(time.time()) - 90000
        token = _make_token({"sub": "u1", "iat": old_iat, "exp": int(time.time()) + 3600})
        result = validate_token(token, SECRET, algorithms=ALGORITHMS_HS)
        assert result.status == ValidationStatus.TOKEN_TOO_OLD
