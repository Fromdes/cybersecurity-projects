"""CLI interface for JWT Validator & Inspector."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click

from project_37.core import (
    ValidationStatus,
    inspect_token,
    validate_token,
)

_STATUS_COLOR: dict[ValidationStatus, str] = {
    ValidationStatus.VALID: "green",
    ValidationStatus.EXPIRED: "red",
    ValidationStatus.NOT_YET_VALID: "yellow",
    ValidationStatus.INVALID_SIGNATURE: "red",
    ValidationStatus.MALFORMED: "red",
    ValidationStatus.DANGEROUS_ALGORITHM: "red",
    ValidationStatus.MISSING_CLAIM: "yellow",
    ValidationStatus.AUDIENCE_MISMATCH: "yellow",
    ValidationStatus.ISSUER_MISMATCH: "yellow",
    ValidationStatus.TOKEN_TOO_OLD: "yellow",
}


def _print_result(result: Any, output_json: bool) -> None:
    if output_json:
        data: dict[str, Any] = {
            "status": result.status.value,
            "fingerprint": result.fingerprint,
            "valid": result.is_valid,
            "errors": result.errors,
            "warnings": result.warnings,
        }
        if result.header:
            data["header"] = result.header.raw
        if result.claims:
            data["claims"] = result.claims.raw
        click.echo(json.dumps(data, indent=2))
    else:
        color = _STATUS_COLOR.get(result.status, "white")
        click.echo(click.style(f"Status : {result.status.value}", fg=color, bold=True))
        click.echo(f"Valid  : {result.is_valid}")
        if result.fingerprint:
            click.echo(f"SHA256 : {result.fingerprint}")
        if result.header:
            click.echo(f"Alg    : {result.header.algorithm}")
            if result.header.key_id:
                click.echo(f"Kid    : {result.header.key_id}")
        if result.claims:
            c = result.claims
            click.echo(f"Sub    : {c.subject}")
            click.echo(f"Iss    : {c.issuer}")
            click.echo(f"Aud    : {c.audience}")
            click.echo(f"Exp    : {c.expiry}")
            click.echo(f"Iat    : {c.issued_at}")
        if result.warnings:
            click.echo(click.style("Warnings:", fg="yellow"))
            for w in result.warnings:
                click.echo(f"  ! {w}")
        if result.errors:
            click.echo(click.style("Errors:", fg="red"))
            for e in result.errors:
                click.echo(f"  x {e}")


@click.group()
def main() -> None:
    """JWT Validator & Inspector — decode, validate, and audit JWTs."""


@main.command("inspect")
@click.argument("token")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def cmd_inspect(token: str, output_json: bool) -> None:
    """Decode and inspect a JWT without signature verification."""
    result = inspect_token(token)
    _print_result(result, output_json)
    if result.status == ValidationStatus.DANGEROUS_ALGORITHM:
        sys.exit(2)


@main.command("validate")
@click.argument("token")
@click.option("--key", "key_source", required=True, help="HMAC secret or path to PEM public key")
@click.option("--alg", "algorithms", multiple=True, help="Allowed algorithm(s) e.g. RS256")
@click.option("--iss", "issuer", default=None, help="Expected issuer claim")
@click.option("--aud", "audience", default=None, help="Expected audience claim")
@click.option("--require", "required_claims", multiple=True, help="Required claim names")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def cmd_validate(
    token: str,
    key_source: str,
    algorithms: tuple[str, ...],
    issuer: str | None,
    audience: str | None,
    required_claims: tuple[str, ...],
    output_json: bool,
) -> None:
    """Validate JWT signature and claims against a key."""
    key_path = Path(key_source)
    if key_path.exists():
        secret_or_key = key_path.read_text().strip()
    else:
        secret_or_key = key_source

    alg_list = list(algorithms) if algorithms else None
    result = validate_token(
        token,
        secret_or_key,
        algorithms=alg_list,
        expected_issuer=issuer,
        expected_audience=audience,
        required_claims=list(required_claims),
    )
    _print_result(result, output_json)
    sys.exit(0 if result.is_valid else 1)
