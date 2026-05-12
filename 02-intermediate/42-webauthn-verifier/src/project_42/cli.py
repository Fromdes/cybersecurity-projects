"""CLI interface for WebAuthn/FIDO2 Verifier."""

from __future__ import annotations

import base64
import json

import click

from project_42.core import (
    ChallengeStore,
    CredentialStore,
    StoredCredential,
    VerificationStatus,
    WebAuthnVerifier,
    build_sample_auth_data,
    parse_authenticator_data,
)


@click.group()
def main() -> None:
    """WebAuthn/FIDO2 Verifier — parse authenticator data and verify ceremonies."""


@main.command("parse-authdata")
@click.argument("base64url_data")
@click.option("--json", "output_json", is_flag=True)
def cmd_parse(base64url_data: str, output_json: bool) -> None:
    """Parse and display WebAuthn authenticator data."""
    padding = base64url_data + "=" * (4 - len(base64url_data) % 4)
    try:
        raw = base64.urlsafe_b64decode(padding)
        auth_data = parse_authenticator_data(raw)
    except (ValueError, Exception) as exc:
        click.echo(click.style(f"Parse error: {exc}", fg="red"), err=True)
        raise SystemExit(1) from exc

    if output_json:
        click.echo(json.dumps({
            "rp_id_hash": auth_data.rp_id_hash.hex(),
            "flags": auth_data.flags,
            "user_present": auth_data.user_present,
            "user_verified": auth_data.user_verified,
            "sign_count": auth_data.sign_count,
            "aaguid": auth_data.aaguid.hex() if auth_data.aaguid else None,
        }, indent=2))
    else:
        click.echo(f"RP ID hash  : {auth_data.rp_id_hash.hex()}")
        click.echo(f"Flags       : 0x{auth_data.flags:02x}")
        click.echo(f"User Present: {auth_data.user_present}")
        click.echo(f"User Verify : {auth_data.user_verified}")
        click.echo(f"Sign Count  : {auth_data.sign_count}")
        if auth_data.aaguid:
            click.echo(f"AAGUID      : {auth_data.aaguid.hex()}")


@main.command("demo")
@click.option("--rp-id", default="example.com", show_default=True)
@click.option("--origin", default="https://example.com", show_default=True)
def cmd_demo(rp_id: str, origin: str) -> None:
    """Run a WebAuthn registration + authentication demo."""
    click.echo("=== WebAuthn/FIDO2 Verifier Demo ===\n")

    verifier = WebAuthnVerifier(rp_id=rp_id, origin=origin)
    challenge_store = ChallengeStore()
    cred_store = CredentialStore()

    # --- Registration ceremony ---
    click.echo("1. Registration ceremony")
    challenge = challenge_store.issue()
    click.echo(f"   Challenge issued: {challenge[:32]}…")

    client_data = json.dumps({
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": origin,
    }).encode()

    r = verifier.verify_client_data(client_data, challenge, "webauthn.create")
    click.echo(click.style(f"   ClientData: {r.status.value}", fg="green" if r.ok else "red"))
    # Consume challenge
    challenge_store.consume(challenge)

    auth_data_bytes = build_sample_auth_data(rp_id, sign_count=1)
    auth_data = parse_authenticator_data(auth_data_bytes)
    r2 = verifier.verify_authenticator_data(auth_data)
    click.echo(click.style(f"   AuthData  : {r2.status.value}", fg="green" if r2.ok else "red"))

    cred = StoredCredential(
        credential_id="demo-cred-id-001",
        user_id="alice",
        rp_id=rp_id,
        sign_count=auth_data.sign_count,
        public_key_pem="(placeholder — real key from authenticator)",
        aaguid="00000000000000000000000000000000",
    )
    cred_store.store(cred)
    click.echo(f"   Credential stored for user: {cred.user_id}")

    # --- Authentication ceremony ---
    click.echo("\n2. Authentication ceremony")
    auth_challenge = challenge_store.issue()
    click.echo(f"   Challenge issued: {auth_challenge[:32]}…")

    auth_client_data = json.dumps({
        "type": "webauthn.get",
        "challenge": auth_challenge,
        "origin": origin,
    }).encode()

    r3 = verifier.verify_client_data(auth_client_data, auth_challenge, "webauthn.get")
    click.echo(click.style(f"   ClientData: {r3.status.value}", fg="green" if r3.ok else "red"))
    challenge_store.consume(auth_challenge)

    auth_data2_bytes = build_sample_auth_data(rp_id, sign_count=2)
    auth_data2 = parse_authenticator_data(auth_data2_bytes)
    r4 = verifier.verify_authenticator_data(auth_data2, stored_sign_count=cred.sign_count)
    click.echo(click.style(f"   AuthData  : {r4.status.value}", fg="green" if r4.ok else "red"))
    if r4.ok and r4.new_sign_count is not None:
        cred.sign_count = r4.new_sign_count
        click.echo(f"   Sign count updated to: {cred.sign_count}")

    # --- Replay attack demo ---
    click.echo("\n3. Replay attack simulation (reused sign counter)")
    r5 = verifier.verify_authenticator_data(auth_data2, stored_sign_count=cred.sign_count)
    verdict = click.style("BLOCKED", fg="green") if r5.status == VerificationStatus.COUNTER_REPLAY else click.style("ALLOWED", fg="red")
    click.echo(f"   Replay attempt: {verdict} ({r5.status.value})")

    click.echo(click.style("\nDemo complete.", fg="green", bold=True))


@main.command("issue-challenge")
@click.option("--json", "output_json", is_flag=True)
def cmd_issue_challenge(output_json: bool) -> None:
    """Generate a fresh WebAuthn challenge."""
    store = ChallengeStore()
    challenge = store.issue()
    if output_json:
        click.echo(json.dumps({"challenge": challenge}, indent=2))
    else:
        click.echo(f"Challenge: {challenge}")
        click.echo("Store this server-side and pass it to the authenticator.")
