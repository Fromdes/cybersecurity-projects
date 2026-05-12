"""CLI interface for Input Sanitization Library."""

from __future__ import annotations

import json
import sys

import click

from project_44.core import (
    detect_threats,
    sanitize_filename,
    sanitize_text,
    validate_email,
    validate_integer,
)


@click.group()
def main() -> None:
    """Input Sanitizer — detect XSS, SQLi, path traversal, and command injection."""


@main.command("scan")
@click.argument("text")
@click.option("--json", "output_json", is_flag=True)
def cmd_scan(text: str, output_json: bool) -> None:
    """Scan text for threats without modifying it."""
    threats = detect_threats(text)
    if output_json:
        click.echo(json.dumps({
            "clean": len(threats) == 0,
            "threats": [{"type": t.threat_type.value, "pattern": t.pattern, "position": t.position} for t in threats],
        }, indent=2))
    else:
        if not threats:
            click.echo(click.style("CLEAN — no threats detected", fg="green"))
        else:
            click.echo(click.style(f"THREATS DETECTED ({len(threats)})", fg="red", bold=True))
            for t in threats:
                click.echo(f"  [{t.threat_type.value:20s}] pos={t.position}  pattern={t.pattern[:60]}")
    sys.exit(0 if not threats else 1)


@main.command("sanitize")
@click.argument("text")
@click.option("--max-len", default=8192, show_default=True)
@click.option("--no-strip-html", is_flag=True)
@click.option("--no-normalize", is_flag=True)
@click.option("--json", "output_json", is_flag=True)
def cmd_sanitize(text: str, max_len: int, no_strip_html: bool, no_normalize: bool, output_json: bool) -> None:
    """Sanitize untrusted text input."""
    result = sanitize_text(
        text,
        max_length=max_len,
        strip_html=not no_strip_html,
        normalize=not no_normalize,
    )
    if output_json:
        click.echo(json.dumps({
            "sanitized": result.sanitized,
            "clean": result.is_clean,
            "truncated": result.truncated,
            "threats": [t.threat_type.value for t in result.threats],
        }, indent=2))
    else:
        color = "green" if result.is_clean else "yellow"
        click.echo(click.style(f"Clean: {result.is_clean}", fg=color))
        if result.threats:
            click.echo(f"Threats: {', '.join(t.threat_type.value for t in result.threats)}")
        click.echo(f"Output : {result.sanitized}")


@main.command("filename")
@click.argument("name")
def cmd_filename(name: str) -> None:
    """Sanitize a user-supplied filename."""
    safe = sanitize_filename(name)
    click.echo(f"Original : {name}")
    click.echo(f"Safe     : {safe}")
    changed = name != safe
    click.echo(click.style(f"Modified : {changed}", fg="yellow" if changed else "green"))


@main.command("validate-email")
@click.argument("email")
def cmd_email(email: str) -> None:
    """Validate an email address structure."""
    ok = validate_email(email)
    click.echo(click.style(f"Valid: {ok}", fg="green" if ok else "red"))
    sys.exit(0 if ok else 1)


@main.command("demo")
def cmd_demo() -> None:
    """Run sanitization examples for common attack patterns."""
    examples: list[tuple[str, str]] = [
        ("XSS script tag", "<script>alert('xss')</script>"),
        ("XSS event handler", '<img src=x onerror="steal()">'),
        ("SQL injection", "' OR '1'='1"),
        ("SQL UNION", "' UNION SELECT * FROM users--"),
        ("Path traversal", "../../etc/passwd"),
        ("Command injection", "file.txt; rm -rf /"),
        ("Null byte", "file\x00.txt"),
        ("Clean text", "Hello, world! This is safe input."),
    ]
    click.echo("=== Input Sanitizer Demo ===\n")
    for label, payload in examples:
        result = sanitize_text(payload)
        color = "green" if result.is_clean else "red"
        status = "CLEAN " if result.is_clean else "THREAT"
        types = ", ".join(t.threat_type.value for t in result.threats) if result.threats else "—"
        click.echo(
            click.style(f"[{status}]", fg=color)
            + f" {label:<25} threats={types}"
        )
