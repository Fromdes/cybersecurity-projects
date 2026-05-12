"""GDPR/KVKK Compliance Auditor CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from project_100.core import ComplianceFinding, audit_inventory_file

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _severity_gte(sev: str, min_sev: str) -> bool:
    """Return True if *sev* is at least as severe as *min_sev*."""
    order = {s: i for i, s in enumerate(_SEVERITIES)}
    return order.get(sev, 99) <= order.get(min_sev, 99)


def _fmt_finding(f: ComplianceFinding, color: bool = True) -> str:
    """Format a single finding for human-readable output."""
    sev_colors = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow", "LOW": "cyan"}
    sev_str = click.style(f"[{f.severity}]", fg=sev_colors.get(f.severity, "white"), bold=True) if color else f"[{f.severity}]"
    return f"  {sev_str} {f.check_id} — {f.title}\n    Asset: {f.asset_name} | {f.article}\n    {f.recommendation}"


@click.group()
@click.version_option(version="0.1.0")
def cli() -> None:
    """GDPR/KVKK Compliance Auditor — audit data asset inventories."""


@cli.command()
@click.argument("inventory", type=click.Path(exists=True, path_type=Path))
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None, help="Write JSON report to file.")
@click.option("--min-severity", default="INFO", type=click.Choice(list(_SEVERITIES)), show_default=True, help="Minimum severity to display.")
@click.option("--exit-code", is_flag=True, default=False, help="Exit 1 if CRITICAL/HIGH findings exist.")
@click.option("--regulation", default=None, type=str, help="Filter findings by regulation (GDPR, KVKK).")
def audit(
    inventory: Path,
    output: Path | None,
    min_severity: str,
    exit_code: bool,
    regulation: str | None,
) -> None:
    """Audit a JSON data asset inventory for GDPR/KVKK compliance."""
    report = audit_inventory_file(inventory)

    filtered: list[ComplianceFinding] = [
        f for f in report.findings
        if _severity_gte(f.severity, min_severity)
        and (regulation is None or regulation.upper() in f.regulation.upper())
    ]

    click.echo(f"\nGDPR/KVKK Compliance Audit — {inventory.name}")
    click.echo(f"Assets audited : {report.assets_audited}")
    click.echo(f"Total findings : {len(report.findings)}")
    click.echo(f"Displayed      : {len(filtered)} (min-severity={min_severity})")
    click.echo(f"Overall status : {'COMPLIANT' if report.compliant else 'NON-COMPLIANT'}\n")

    if filtered:
        click.echo("Findings:")
        for f in filtered:
            click.echo(_fmt_finding(f))
            click.echo()
    else:
        click.echo("No findings match the filter criteria.")

    if output:
        data = report.to_dict()
        data["filtered_findings"] = [f.to_dict() for f in filtered]
        output.write_text(json.dumps(data, indent=2), encoding="utf-8")
        click.echo(f"Report written to {output}")

    if exit_code and not report.compliant:
        sys.exit(1)
