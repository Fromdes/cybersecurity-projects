"""CLI interface for Session Manager Service."""

from __future__ import annotations

import json
import sys
import time

import click

from project_41.core import SessionStore

_store = SessionStore()


def _session_to_dict(s: object) -> dict:  # type: ignore[type-arg]
    from project_41.core import Session
    assert isinstance(s, Session)
    return {
        "session_id": s.session_id[:16] + "…",
        "user_id": s.user_id,
        "status": s.status.value,
        "created_at": s.created_at,
        "expires_at": s.expires_at,
        "last_accessed": s.last_accessed,
        "ip_address": s.ip_address,
        "is_valid": s.is_valid,
    }


@click.group()
def main() -> None:
    """Session Manager — create, validate, rotate, and revoke sessions."""


@main.command("create")
@click.option("--user", "user_id", required=True, help="User ID")
@click.option("--ip", default=None, help="Client IP address")
@click.option("--ua", default=None, help="User-Agent string")
@click.option("--ttl", default=3600, show_default=True, help="Session TTL seconds")
@click.option("--json", "output_json", is_flag=True)
def cmd_create(user_id: str, ip: str | None, ua: str | None, ttl: int, output_json: bool) -> None:
    """Create a new session for a user."""
    store = SessionStore(ttl=ttl)
    session = store.create(user_id, ip_address=ip, user_agent=ua)
    if output_json:
        click.echo(json.dumps({
            "session_id": session.session_id,
            "csrf_token": session.csrf_token,
            "expires_at": session.expires_at,
            "user_id": session.user_id,
        }, indent=2))
    else:
        click.echo(click.style("Session created", fg="green"))
        click.echo(f"Session ID : {session.session_id}")
        click.echo(f"CSRF Token : {session.csrf_token}")
        click.echo(f"Expires    : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session.expires_at))}")
        click.echo(click.style("Store the session ID in an HttpOnly, Secure, SameSite=Strict cookie.", fg="yellow"))


@main.command("validate")
@click.argument("session_id")
@click.option("--json", "output_json", is_flag=True)
def cmd_validate(session_id: str, output_json: bool) -> None:
    """Validate a session token (uses shared in-process store demo)."""
    # Demo: create a quick session and validate it
    store = SessionStore()
    demo = store.create("demo-user")
    result = store.validate(demo.session_id)
    if output_json:
        click.echo(json.dumps({"valid": result.valid, "reason": result.reason}, indent=2))
    else:
        color = "green" if result.valid else "red"
        click.echo(click.style(f"Valid: {result.valid} ({result.reason})", fg=color))
    sys.exit(0 if result.valid else 1)


@main.command("demo")
def cmd_demo() -> None:
    """Run a full session lifecycle demo (create → validate → rotate → revoke)."""
    store = SessionStore(ttl=60, idle_timeout=30)
    click.echo("=== Session Manager Demo ===\n")

    click.echo("1. Creating session for user 'alice'...")
    s = store.create("alice", ip_address="192.168.1.10", user_agent="DemoClient/1.0")
    click.echo(f"   session_id  : {s.session_id[:32]}…")
    click.echo(f"   csrf_token  : {s.csrf_token[:32]}…")

    click.echo("\n2. Validating session...")
    r = store.validate(s.session_id)
    click.echo(click.style(f"   Valid: {r.valid} ({r.reason})", fg="green" if r.valid else "red"))

    click.echo("\n3. Verifying CSRF token...")
    ok = store.verify_csrf(s.session_id, s.csrf_token)
    click.echo(click.style(f"   CSRF match: {ok}", fg="green" if ok else "red"))
    bad = store.verify_csrf(s.session_id, "bad-token")
    click.echo(click.style(f"   CSRF mismatch rejected: {not bad}", fg="green"))

    click.echo("\n4. Rotating session (post privilege-change)...")
    new_s = store.rotate(s.session_id)
    click.echo(f"   new session_id: {new_s.session_id[:32]}…")
    r2 = store.validate(new_s.session_id)
    click.echo(click.style(f"   New session valid: {r2.valid}", fg="green"))

    click.echo("\n5. Revoking session...")
    store.revoke(new_s.session_id)
    r3 = store.validate(new_s.session_id)
    click.echo(click.style(f"   After revoke valid: {r3.valid} ({r3.reason})", fg="green"))

    click.echo("\n6. Creating a second session then revoking all...")
    store.create("alice")
    store.create("alice")
    n = store.revoke_all("alice")
    click.echo(f"   Revoked {n} sessions for alice")
    click.echo(click.style("\nDemo complete.", fg="green", bold=True))
