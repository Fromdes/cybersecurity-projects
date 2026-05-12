"""CLI interface for Output Encoder."""

from __future__ import annotations

import json
import sys

import click

from project_45.core import (
    OutputContext,
    encode,
    encode_css_value,
    encode_html_attr,
    encode_html_body,
    encode_js_string,
    encode_json_value,
    encode_shell_arg,
    encode_url_param,
    encode_url_path,
)

_CONTEXT_CHOICES = [c.value for c in OutputContext]


@click.group()
def main() -> None:
    """Output Encoder — context-aware encoding for HTML, JS, URL, CSS, JSON, Shell."""


@main.command("encode")
@click.argument("value")
@click.option("--context", "-c", required=True,
              type=click.Choice(_CONTEXT_CHOICES), help="Output context")
@click.option("--json", "output_json", is_flag=True)
def cmd_encode(value: str, context: str, output_json: bool) -> None:
    """Encode a string for a specific output context."""
    ctx = OutputContext(context)
    try:
        result = encode(value, ctx)
    except ValueError as exc:
        click.echo(click.style(f"Encoding rejected: {exc}", fg="red"), err=True)
        sys.exit(1)

    if output_json:
        click.echo(json.dumps({"context": context, "input": value, "output": result}, indent=2))
    else:
        click.echo(result)


@main.command("demo")
def cmd_demo() -> None:
    """Show all encoders applied to a common XSS payload."""
    payload = """<script>alert('xss"&test')</script>"""
    click.echo(f"Input    : {payload!r}\n")
    contexts: list[tuple[str, str]] = [
        ("html_body", encode_html_body(payload)),
        ("html_attr", encode_html_attr(payload)),
        ("js_string", encode_js_string(payload)),
        ("url_param", encode_url_param(payload)),
        ("url_path", encode_url_path(payload)),
        ("json_value", encode_json_value(payload)),
        ("shell_arg", encode_shell_arg(payload)),
    ]
    for ctx, result in contexts:
        click.echo(f"[{ctx:12s}] {result}")

    click.echo("\n--- CSS (safe value) ---")
    try:
        css_result = encode_css_value("color: red; font-size: 14px")
        click.echo(f"[css_value   ] {css_result}")
    except ValueError as exc:
        click.echo(click.style(f"[css_value   ] REJECTED: {exc}", fg="red"))

    click.echo("\n--- CSS (dangerous expression) ---")
    try:
        encode_css_value("expression(alert(1))")
        click.echo("[css_value   ] ALLOWED (BUG!)")
    except ValueError as exc:
        click.echo(click.style(f"[css_value   ] REJECTED: {exc}", fg="green"))


@main.command("compare")
@click.argument("value")
def cmd_compare(value: str) -> None:
    """Show value encoded in all contexts side by side."""
    click.echo(f"Input: {value!r}\n")
    for ctx in OutputContext:
        try:
            result = encode(value, ctx)
            click.echo(f"[{ctx.value:12s}] {result}")
        except ValueError as exc:
            click.echo(click.style(f"[{ctx.value:12s}] REJECTED: {exc}", fg="red"))
