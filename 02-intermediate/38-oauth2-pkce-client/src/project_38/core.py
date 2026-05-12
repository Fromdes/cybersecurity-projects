"""OAuth2 PKCE Client — core PKCE and token-exchange logic.

Defends against: T1550.001 (App Access Token abuse), T1078 (Valid Accounts),
T1528 (Steal Application Access Token).
Implements RFC 7636 Proof Key for Code Exchange.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import requests

logger = logging.getLogger(__name__)

VERIFIER_MIN_BYTES: int = 32
VERIFIER_MAX_BYTES: int = 96
STATE_BYTES: int = 16
TOKEN_ENDPOINT_TIMEOUT: int = 10


@dataclass(frozen=True)
class PKCEChallenge:
    """PKCE code verifier + S256 challenge pair."""

    code_verifier: str
    code_challenge: str
    code_challenge_method: str = "S256"
    state: str = field(default_factory=lambda: secrets.token_urlsafe(STATE_BYTES))

    def __post_init__(self) -> None:
        if len(self.code_verifier) < VERIFIER_MIN_BYTES:
            raise ValueError("code_verifier too short (RFC 7636 §4.1)")


@dataclass(frozen=True)
class TokenResponse:
    """OAuth2 token endpoint response."""

    access_token: str
    token_type: str
    expires_in: int | None
    refresh_token: str | None
    scope: str | None
    id_token: str | None
    raw: dict[str, Any]


@dataclass(frozen=True)
class AuthorizationURL:
    """Built authorization URL with PKCE parameters."""

    url: str
    pkce: PKCEChallenge


def generate_pkce_challenge(verifier_bytes: int = VERIFIER_MIN_BYTES) -> PKCEChallenge:
    """Generate a cryptographically random PKCE code verifier and S256 challenge.

    Args:
        verifier_bytes: Random bytes for verifier (32–96, default 32).

    Returns:
        PKCEChallenge with verifier, challenge, and random state.
    """
    if not (VERIFIER_MIN_BYTES <= verifier_bytes <= VERIFIER_MAX_BYTES):
        raise ValueError(f"verifier_bytes must be {VERIFIER_MIN_BYTES}–{VERIFIER_MAX_BYTES}")

    raw_verifier = secrets.token_bytes(verifier_bytes)
    code_verifier = base64.urlsafe_b64encode(raw_verifier).rstrip(b"=").decode()

    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    return PKCEChallenge(
        code_verifier=code_verifier,
        code_challenge=code_challenge,
        state=secrets.token_urlsafe(STATE_BYTES),
    )


def build_authorization_url(
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    pkce: PKCEChallenge,
    extra_params: dict[str, str] | None = None,
) -> AuthorizationURL:
    """Build the OAuth2 authorization URL with PKCE parameters.

    Args:
        authorization_endpoint: IdP authorization endpoint URL.
        client_id: OAuth2 client_id.
        redirect_uri: Registered redirect URI.
        scope: Space-separated scopes.
        pkce: PKCEChallenge from generate_pkce_challenge().
        extra_params: Optional additional query parameters.

    Returns:
        AuthorizationURL containing the full URL and the PKCE object.
    """
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": pkce.state,
        "code_challenge": pkce.code_challenge,
        "code_challenge_method": pkce.code_challenge_method,
    }
    if extra_params:
        params.update(extra_params)

    url = authorization_endpoint + "?" + urllib.parse.urlencode(params)
    logger.debug("Authorization URL built client_id=%s scope=%s", client_id, scope)
    return AuthorizationURL(url=url, pkce=pkce)


def exchange_code_for_tokens(
    token_endpoint: str,
    code: str,
    code_verifier: str,
    client_id: str,
    redirect_uri: str,
    *,
    client_secret: str | None = None,
    timeout: int = TOKEN_ENDPOINT_TIMEOUT,
    session: requests.Session | None = None,
) -> TokenResponse:
    """Exchange an authorization code for tokens using PKCE verifier.

    Args:
        token_endpoint: IdP token endpoint URL.
        code: Authorization code from callback.
        code_verifier: PKCE verifier generated earlier.
        client_id: OAuth2 client_id.
        redirect_uri: Redirect URI used in authorization request.
        client_secret: Optional client secret (for confidential clients).
        timeout: HTTP request timeout in seconds.
        session: Optional requests.Session for dependency injection.

    Returns:
        TokenResponse with access_token and related fields.

    Raises:
        requests.HTTPError: On non-2xx responses.
        ValueError: On malformed response.
    """
    data: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    if client_secret:
        data["client_secret"] = client_secret

    http = session or requests.Session()
    response = http.post(token_endpoint, data=data, timeout=timeout)

    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        logger.error("Token exchange failed status=%s body=%s", response.status_code, response.text[:200])
        raise

    body: dict[str, Any] = response.json()
    if "access_token" not in body:
        raise ValueError(f"Token response missing access_token: {body}")

    logger.info("Token exchange succeeded token_type=%s expires_in=%s", body.get("token_type"), body.get("expires_in"))
    return TokenResponse(
        access_token=body["access_token"],
        token_type=body.get("token_type", "Bearer"),
        expires_in=body.get("expires_in"),
        refresh_token=body.get("refresh_token"),
        scope=body.get("scope"),
        id_token=body.get("id_token"),
        raw=body,
    )


def verify_state(returned_state: str, original_state: str) -> None:
    """Constant-time state parameter verification (CSRF protection).

    Args:
        returned_state: State value returned by IdP in callback.
        original_state: State value sent in the authorization request.

    Raises:
        ValueError: If state values do not match.
    """
    if not secrets.compare_digest(returned_state, original_state):
        raise ValueError("State mismatch — possible CSRF attack")


def describe_pkce(pkce: PKCEChallenge) -> dict[str, str]:
    """Return a safe-to-display summary of a PKCE challenge (no verifier).

    Args:
        pkce: PKCEChallenge to describe.

    Returns:
        Dict with challenge and method; verifier intentionally omitted.
    """
    return {
        "code_challenge": pkce.code_challenge,
        "code_challenge_method": pkce.code_challenge_method,
        "state": pkce.state,
        "verifier_length": str(len(pkce.code_verifier)),
    }
