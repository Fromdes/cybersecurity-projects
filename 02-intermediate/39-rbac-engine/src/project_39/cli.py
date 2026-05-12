"""CLI interface for RBAC Engine."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import yaml

from project_39.core import RBACEngine


def _load_engine(policy_file: str) -> RBACEngine:
    path = Path(policy_file)
    if not path.exists():
        click.echo(f"Policy file not found: {policy_file}", err=True)
        sys.exit(1)
    return RBACEngine.from_yaml(path.read_text())


@click.group()
def main() -> None:
    """RBAC Engine — define roles/permissions and check access."""


@main.command("check")
@click.option("--policy", required=True, help="Path to YAML policy file")
@click.option("--user", "user_id", required=True, help="User ID to check")
@click.option("--resource", required=True, help="Resource name")
@click.option("--action", required=True, help="Action name")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def cmd_check(policy: str, user_id: str, resource: str, action: str, output_json: bool) -> None:
    """Check if a user has access to resource:action."""
    engine = _load_engine(policy)
    decision = engine.check(user_id, resource, action)

    if output_json:
        click.echo(json.dumps({
            "allowed": decision.allowed,
            "user_id": decision.user_id,
            "resource": decision.resource,
            "action": decision.action,
            "matched_role": decision.matched_role,
            "matched_permission": decision.matched_permission,
        }, indent=2))
    else:
        color = "green" if decision.allowed else "red"
        verdict = "ALLOW" if decision.allowed else "DENY"
        click.echo(click.style(verdict, fg=color, bold=True))
        click.echo(f"User     : {decision.user_id}")
        click.echo(f"Resource : {decision.resource}")
        click.echo(f"Action   : {decision.action}")
        if decision.matched_role:
            click.echo(f"Via role : {decision.matched_role}")
        if decision.matched_permission:
            click.echo(f"Via perm : {decision.matched_permission}")

    sys.exit(0 if decision.allowed else 1)


@main.command("list-permissions")
@click.option("--policy", required=True, help="Path to YAML policy file")
@click.option("--user", "user_id", required=True, help="User ID")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def cmd_list_permissions(policy: str, user_id: str, output_json: bool) -> None:
    """List all effective permissions for a user."""
    engine = _load_engine(policy)
    try:
        perms = engine.list_user_permissions(user_id)
    except KeyError as exc:
        click.echo(click.style(f"Error: {exc}", fg="red"), err=True)
        sys.exit(1)

    if output_json:
        click.echo(json.dumps({"user_id": user_id, "permissions": perms}, indent=2))
    else:
        click.echo(f"User: {user_id}")
        if perms:
            for p in perms:
                click.echo(f"  {p}")
        else:
            click.echo("  (no permissions)")


@main.command("dump")
@click.option("--policy", required=True, help="Path to YAML policy file")
def cmd_dump(policy: str) -> None:
    """Dump the loaded policy as JSON for inspection."""
    engine = _load_engine(policy)
    click.echo(json.dumps(engine.to_dict(), indent=2))


@main.command("init-policy")
@click.option("--output", default="policy.yaml", show_default=True, help="Output YAML file")
def cmd_init_policy(output: str) -> None:
    """Write a sample RBAC policy YAML."""
    sample = {
        "roles": {
            "viewer": {
                "permissions": ["reports:read", "dashboard:view"],
                "parents": [],
            },
            "editor": {
                "permissions": ["reports:write", "reports:delete"],
                "parents": ["viewer"],
            },
            "admin": {
                "permissions": ["*:*"],
                "parents": ["editor"],
            },
        },
        "users": {
            "alice": {"roles": ["admin"]},
            "bob": {"roles": ["editor"]},
            "carol": {"roles": ["viewer"]},
        },
    }
    Path(output).write_text(yaml.dump(sample, default_flow_style=False))
    click.echo(f"Sample policy written to {output}")
