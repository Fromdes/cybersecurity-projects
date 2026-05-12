"""CLI interface for ABAC Policy Engine."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import yaml

from project_40.core import ABACEngine, AttributeSet


def _load_engine(policy_file: str) -> ABACEngine:
    path = Path(policy_file)
    if not path.exists():
        click.echo(f"Policy file not found: {policy_file}", err=True)
        sys.exit(1)
    return ABACEngine.from_yaml(path.read_text())


def _parse_attrs(attr_strings: tuple[str, ...]) -> dict[str, str | int | float]:
    """Parse key=value strings into a dict, coercing numbers."""
    result: dict[str, str | int | float] = {}
    for item in attr_strings:
        if "=" not in item:
            raise click.BadParameter(f"Attribute must be key=value, got: {item}")
        k, v = item.split("=", 1)
        try:
            result[k] = int(v)
        except ValueError:
            try:
                result[k] = float(v)
            except ValueError:
                result[k] = v
    return result


@click.group()
def main() -> None:
    """ABAC Policy Engine — evaluate attribute-based access control policies."""


@main.command("evaluate")
@click.option("--policy", required=True, help="Path to YAML policy file")
@click.option("--subject", "-s", multiple=True, help="Subject attribute key=value (repeatable)")
@click.option("--resource", "-r", multiple=True, help="Resource attribute key=value (repeatable)")
@click.option("--environment", "-e", multiple=True, help="Environment attribute key=value (repeatable)")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def cmd_evaluate(
    policy: str,
    subject: tuple[str, ...],
    resource: tuple[str, ...],
    environment: tuple[str, ...],
    output_json: bool,
) -> None:
    """Evaluate ABAC policy for a request context."""
    engine = _load_engine(policy)

    try:
        subj_attrs = _parse_attrs(subject)
        res_attrs = _parse_attrs(resource)
        env_attrs = _parse_attrs(environment)
    except click.BadParameter as exc:
        click.echo(click.style(str(exc), fg="red"), err=True)
        sys.exit(1)

    decision = engine.evaluate(
        AttributeSet.from_dict(subj_attrs),
        AttributeSet.from_dict(res_attrs),
        AttributeSet.from_dict(env_attrs),
    )

    if output_json:
        click.echo(json.dumps({
            "allowed": decision.allowed,
            "effect": decision.effect.value if decision.effect else None,
            "matched_rule": decision.matched_rule,
            "subject": decision.subject_attrs,
            "resource": decision.resource_attrs,
        }, indent=2))
    else:
        color = "green" if decision.allowed else "red"
        verdict = "PERMIT" if decision.allowed else "DENY"
        click.echo(click.style(verdict, fg=color, bold=True))
        click.echo(f"Rule   : {decision.matched_rule or '(none matched)'}")
        click.echo(f"Effect : {decision.effect.value if decision.effect else 'not-applicable'}")

    sys.exit(0 if decision.allowed else 1)


@main.command("dump")
@click.option("--policy", required=True, help="Path to YAML policy file")
def cmd_dump(policy: str) -> None:
    """Dump parsed policy as JSON."""
    engine = _load_engine(policy)
    click.echo(json.dumps(engine.to_dict(), indent=2))


@main.command("init-policy")
@click.option("--output", default="abac-policy.yaml", show_default=True)
def cmd_init_policy(output: str) -> None:
    """Write a sample ABAC policy YAML."""
    sample = {
        "combining_algorithm": "deny-overrides",
        "rules": [
            {
                "name": "deny-external-sensitive",
                "effect": "deny",
                "priority": 100,
                "description": "External users cannot access sensitive resources",
                "conditions": [
                    {"attribute": "subject.location", "operator": "eq", "value": "external"},
                    {"attribute": "resource.classification", "operator": "eq", "value": "sensitive"},
                ],
            },
            {
                "name": "permit-owner-read",
                "effect": "permit",
                "priority": 10,
                "description": "Resource owner can always read their own resource",
                "conditions": [
                    {"attribute": "subject.user_id", "operator": "eq", "value": "owner"},
                    {"attribute": "resource.action", "operator": "eq", "value": "read"},
                ],
            },
            {
                "name": "permit-admin-all",
                "effect": "permit",
                "priority": 50,
                "description": "Admins can do anything",
                "conditions": [
                    {"attribute": "subject.role", "operator": "eq", "value": "admin"},
                ],
            },
        ],
    }
    Path(output).write_text(yaml.dump(sample, default_flow_style=False))
    click.echo(f"Sample ABAC policy written to {output}")
