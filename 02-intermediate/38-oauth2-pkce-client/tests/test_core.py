"""Tests for OAuth2 PKCE Client core logic."""

from __future__ import annotations

import base64
import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from project_38.core import (
    PKCEChallenge,
    build_authorization_url,
    describe_pkce,
    exchange_code_for_tokens,
    generate_pkce_challenge,
    verify_state,
)


class TestGeneratePKCEChallenge:
    def test_default_lengths(self) -> None:
        pkce = generate_pkce_challenge()
        assert len(pkce.code_verifier) > 0
        assert len(pkce.code_challenge) > 0
        assert pkce.code_challenge_method == "S256"

    def test_challenge_is_s256_of_verifier(self) -> None:
        pkce = generate_pkce_challenge()
        digest = hashlib.sha256(pkce.code_verifier.encode()).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        assert pkce.code_challenge == expected

    def test_state_is_random(self) -> None:
        p1 = generate_pkce_challenge()
        p2 = generate_pkce_challenge()
        assert p1.state != p2.state

    def test_verifiers_are_unique(self) -> None:
        p1 = generate_pkce_challenge()
        p2 = generate_pkce_challenge()
        assert p1.code_verifier != p2.code_verifier

    def test_invalid_bytes_too_small(self) -> None:
        with pytest.raises(ValueError):
            generate_pkce_challenge(verifier_bytes=8)

    def test_invalid_bytes_too_large(self) -> None:
        with pytest.raises(ValueError):
            generate_pkce_challenge(verifier_bytes=200)

    def test_custom_bytes(self) -> None:
        pkce = generate_pkce_challenge(verifier_bytes=64)
        assert len(pkce.code_verifier) > 0


class TestBuildAuthorizationURL:
    def test_contains_required_params(self) -> None:
        pkce = generate_pkce_challenge()
        auth = build_authorization_url(
            "https://auth.example.com/authorize",
            "my-client",
            "http://localhost:8080/callback",
            "openid profile",
            pkce,
        )
        assert "response_type=code" in auth.url
        assert "client_id=my-client" in auth.url
        assert "code_challenge=" in auth.url
        assert "code_challenge_method=S256" in auth.url
        assert f"state={pkce.state}" in auth.url

    def test_extra_params_included(self) -> None:
        pkce = generate_pkce_challenge()
        auth = build_authorization_url(
            "https://auth.example.com/authorize",
            "client",
            "http://localhost/cb",
            "openid",
            pkce,
            extra_params={"prompt": "consent"},
        )
        assert "prompt=consent" in auth.url


class TestVerifyState:
    def test_matching_state_passes(self) -> None:
        verify_state("abc123", "abc123")

    def test_mismatched_state_raises(self) -> None:
        with pytest.raises(ValueError, match="State mismatch"):
            verify_state("abc123", "xyz789")


class TestExchangeCodeForTokens:
    def test_successful_exchange(self) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "tok_abc",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_response.raise_for_status = MagicMock()

        mock_session = MagicMock()
        mock_session.post.return_value = mock_response

        result = exchange_code_for_tokens(
            "https://auth.example.com/token",
            "code123",
            "verifier456",
            "client_id",
            "http://localhost/cb",
            session=mock_session,
        )
        assert result.access_token == "tok_abc"
        assert result.token_type == "Bearer"
        assert result.expires_in == 3600

    def test_missing_access_token_raises(self) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"error": "invalid_grant"}
        mock_response.raise_for_status = MagicMock()

        mock_session = MagicMock()
        mock_session.post.return_value = mock_response

        with pytest.raises(ValueError, match="access_token"):
            exchange_code_for_tokens(
                "https://auth.example.com/token",
                "bad_code",
                "verifier",
                "client_id",
                "http://localhost/cb",
                session=mock_session,
            )

    def test_http_error_propagates(self) -> None:
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("401")
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        mock_session = MagicMock()
        mock_session.post.return_value = mock_response

        with pytest.raises(requests.HTTPError):
            exchange_code_for_tokens(
                "https://auth.example.com/token",
                "code",
                "verifier",
                "client_id",
                "http://localhost/cb",
                session=mock_session,
            )


class TestDescribePKCE:
    def test_no_verifier_in_output(self) -> None:
        pkce = generate_pkce_challenge()
        info = describe_pkce(pkce)
        assert "code_verifier" not in info
        assert "code_challenge" in info
        assert info["code_challenge_method"] == "S256"
