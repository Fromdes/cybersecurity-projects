"""CLI interface for OAuth2 PKCE Client."""

from __future__ import annotations

import json
import sys

import click

from project_38.core import (
    build_authorization_url,
    describe_pkce,
    exchange_code_for_tokens,
    generate_pkce_challenge,
    verify_state,
)


@click.group()
def main() -> None:
    """OAuth2 PKCE Client — generate challenges, build auth URLs, exchange codes."""


@main.command("challenge")
@click.option("--bytes", "verifier_bytes", default=32, show_default=True, help="Verifier entropy bytes (32-96)")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def cmd_challenge(verifier_bytes: int, output_json: bool) -> None:
    """Generate a PKCE code_verifier + S256 challenge."""
    pkce = generate_pkce_challenge(verifier_bytes)
    if output_json:
        click.echo(json.dumps({
            "code_verifier": pkce.code_verifier,
            "code_challenge": pkce.code_challenge,
            "code_challenge_method": pkce.code_challenge_method,
            "state": pkce.state,
        }, indent=2))
    else:
        click.echo(f"Verifier  : {pkce.code_verifier}")
        click.echo(f"Challenge : {pkce.code_challenge}")
        click.echo(f"Method    : {pkce.code_challenge_method}")
        click.echo(f"State     : {pkce.state}")
        click.echo(click.style("WARNING: Keep the verifier secret — never log or transmit it.", fg="yellow"))


@main.command("auth-url")
@click.option("--endpoint", required=True, help="Authorization endpoint URL")
@click.option("--client-id", required=True, help="OAuth2 client_id")
@click.option("--redirect-uri", required=True, help="Registered redirect URI")
@click.option("--scope", default="openid profile email", show_default=True, help="Space-separated scopes")
@click.option("--verifier", default=None, help="Existing code_verifier (omit to generate new)")
@click.option("--state", default=None, help="Existing state (omit to generate random)")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def cmd_auth_url(
    endpoint: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    verifier: str | None,
    state: str | None,
    output_json: bool,
) -> None:
    """Build an OAuth2 authorization URL with PKCE parameters."""
    if verifier:
        import base64
        import hashlib
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        from project_38.core import PKCEChallenge
        pkce = PKCEChallenge(
            code_verifier=verifier,
            code_challenge=challenge,
            state=state or __import__("secrets").token_urlsafe(16),
        )
    else:
        pkce = generate_pkce_challenge()

    auth = build_authorization_url(endpoint, client_id, redirect_uri, scope, pkce)
    if output_json:
        click.echo(json.dumps({"url": auth.url, "pkce": describe_pkce(pkce)}, indent=2))
    else:
        click.echo(f"Open this URL in a browser:\n\n{auth.url}\n")
        click.echo(f"Save your verifier: {pkce.code_verifier}")
        click.echo(f"Expected state   : {pkce.state}")


@main.command("exchange")
@click.option("--token-endpoint", required=True, help="Token endpoint URL")
@click.option("--code", required=True, help="Authorization code from callback")
@click.option("--verifier", required=True, help="PKCE code_verifier")
@click.option("--client-id", required=True, help="OAuth2 client_id")
@click.option("--redirect-uri", required=True, help="Redirect URI")
@click.option("--client-secret", default=None, help="Client secret (confidential clients)")
@click.option("--state", default=None, help="Original state to verify")
@click.option("--returned-state", default=None, help="State returned by IdP (for verification)")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def cmd_exchange(
    token_endpoint: str,
    code: str,
    verifier: str,
    client_id: str,
    redirect_uri: str,
    client_secret: str | None,
    state: str | None,
    returned_state: str | None,
    output_json: bool,
) -> None:
    """Exchange an authorization code for tokens via PKCE."""
    if state and returned_state:
        try:
            verify_state(returned_state, state)
        except ValueError as exc:
            click.echo(click.style(f"CSRF check failed: {exc}", fg="red"), err=True)
            sys.exit(2)

    try:
        tokens = exchange_code_for_tokens(
            token_endpoint,
            code,
            verifier,
            client_id,
            redirect_uri,
            client_secret=client_secret,
        )
    except Exception as exc:
        click.echo(click.style(f"Token exchange failed: {exc}", fg="red"), err=True)
        sys.exit(1)

    if output_json:
        click.echo(json.dumps({
            "access_token": tokens.access_token[:20] + "…(truncated)",
            "token_type": tokens.token_type,
            "expires_in": tokens.expires_in,
            "scope": tokens.scope,
            "has_refresh_token": tokens.refresh_token is not None,
            "has_id_token": tokens.id_token is not None,
        }, indent=2))
    else:
        click.echo(click.style("Token exchange succeeded.", fg="green"))
        click.echo(f"Type     : {tokens.token_type}")
        click.echo(f"Expires  : {tokens.expires_in}s")
        click.echo(f"Scope    : {tokens.scope}")
        click.echo(f"Refresh  : {'yes' if tokens.refresh_token else 'no'}")
        click.echo(f"ID token : {'yes' if tokens.id_token else 'no'}")
