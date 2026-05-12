"""CLI for Snort/Suricata Rule Generator."""

from __future__ import annotations

import sys

import click

from .core import (
    RuleBuilder,
    sql_injection_rule,
    ssh_brute_force_rule,
    validate_rule,
    xss_rule,
)


@click.group()
def cli() -> None:
    """Snort/Suricata Rule Generator — build and validate IDS rules."""


@cli.command("presets")
@click.option("--type", "rule_type",
              type=click.Choice(["sqli", "xss", "ssh-brute"]),
              default="sqli", show_default=True)
def presets_cmd(rule_type: str) -> None:
    """Print a preset IDS rule."""
    rule_map = {
        "sqli": sql_injection_rule,
        "xss": xss_rule,
        "ssh-brute": ssh_brute_force_rule,
    }
    rule = rule_map[rule_type]()
    errors = validate_rule(rule)
    if errors:
        for e in errors:
            click.echo(f"[error] {e.field}: {e.message}", err=True)
        sys.exit(1)
    click.echo(rule.render())


@cli.command("build")
@click.option("--action", default="alert", show_default=True)
@click.option("--protocol", default="tcp", show_default=True)
@click.option("--src", default="any", show_default=True)
@click.option("--src-port", default="any", show_default=True)
@click.option("--dst", default="any", show_default=True)
@click.option("--dst-port", default="any", show_default=True)
@click.option("--msg", required=True, help="Alert message.")
@click.option("--content", "contents", multiple=True, help="Content match strings.")
@click.option("--classtype", default="misc-activity", show_default=True)
def build_cmd(
    action: str, protocol: str, src: str, src_port: str,
    dst: str, dst_port: str, msg: str, contents: tuple[str, ...],
    classtype: str,
) -> None:
    """Build a custom Snort/Suricata rule."""
    builder = (
        RuleBuilder()
        .action(action)
        .protocol(protocol)
        .src(src, src_port)
        .dst(dst, dst_port)
        .msg(msg)
        .classtype(classtype)
    )
    for c in contents:
        builder.content(c)
    rule = builder.build()
    errors = validate_rule(rule)
    if errors:
        for e in errors:
            click.echo(f"[error] {e.field}: {e.message}", err=True)
        sys.exit(1)
    click.echo(rule.render())
