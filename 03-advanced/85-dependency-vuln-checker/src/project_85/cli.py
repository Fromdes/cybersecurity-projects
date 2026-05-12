"""Dependency Vulnerability Checker — CLI interface."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click

from project_85.core import (
    Dependency,
    ScanSummary,
    detect_and_parse,
    query_osv_batch,
    query_osv_single,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Dependency Vulnerability Checker — query OSV.dev for CVEs in your dependencies."""


@cli.command("check")
@click.argument("manifest", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--exit-code", is_flag=True, default=False,
              help="Exit 1 if any vulnerabilities found (for CI).")
@click.option("--offline", is_flag=True, default=False,
              help="Skip API calls (dry run for testing).")
def check_cmd(manifest: Path, output: Path | None, exit_code: bool, offline: bool) -> None:
    """Check a dependency manifest for known vulnerabilities via OSV.dev."""
    try:
        deps = detect_and_parse(manifest)
    except (ValueError, OSError) as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Checking {len(deps)} dependencies from {manifest.name} …")

    if offline:
        click.echo("(offline mode — skipping API queries)")
        results = []
    else:
        results = query_osv_batch(deps)

    vulnerable = [r for r in results if r.is_vulnerable]
    errors = [r for r in results if r.error]
    total_vulns = sum(len(r.vulnerabilities) for r in results)
    by_severity: dict[str, int] = {}
    for r in results:
        for v in r.vulnerabilities:
            by_severity[v.severity] = by_severity.get(v.severity, 0) + 1

    summary = ScanSummary(
        total_deps=len(deps),
        vulnerable_count=len(vulnerable),
        total_vulns=total_vulns,
        results=results,
        by_severity=by_severity,
    )

    click.echo(f"\nResults: {len(deps)} packages checked, {len(vulnerable)} vulnerable, {total_vulns} CVE(s)")
    if by_severity:
        click.echo("Severity breakdown: " + ", ".join(f"{k}={v}" for k, v in by_severity.items()))

    for result in vulnerable:
        dep = result.dependency
        click.echo(f"\n{'─'*60}")
        click.echo(click.style(f"{dep.name} {dep.version}", fg="red") + f" ({dep.ecosystem})")
        for vuln in result.vulnerabilities[:5]:
            color = {"CRITICAL": "bright_red", "HIGH": "red", "MODERATE": "yellow", "LOW": "cyan"}.get(
                vuln.severity, "white"
            )
            click.echo(
                "  " + click.style(f"[{vuln.severity}]", fg=color)
                + f" {vuln.vuln_id} — {vuln.summary[:80]}"
            )
            if vuln.fixed_version:
                click.echo(f"     Fix: upgrade to {vuln.fixed_version}")

    if errors:
        click.echo(f"\n{len(errors)} package(s) had errors (network unavailable?).")

    if output:
        output.write_text(json.dumps(summary.to_dict(), indent=2))
        click.echo(f"\nReport saved to {output}")

    if exit_code and len(vulnerable) > 0:
        sys.exit(1)


@cli.command("query")
@click.argument("package")
@click.argument("version")
@click.option("--ecosystem", default="PyPI", show_default=True)
def query_cmd(package: str, version: str, ecosystem: str) -> None:
    """Query OSV.dev for a single package version."""
    dep = Dependency(name=package, version=version, ecosystem=ecosystem)
    click.echo(f"Querying OSV for {package} {version} ({ecosystem}) …")
    result = query_osv_single(dep)
    if result.error:
        click.echo(f"ERROR: {result.error}", err=True)
        return
    if not result.vulnerabilities:
        click.echo(click.style("No known vulnerabilities.", fg="green"))
        return
    click.echo(f"{len(result.vulnerabilities)} vulnerability/ies found:")
    for v in result.vulnerabilities:
        click.echo(f"  [{v.severity}] {v.vuln_id} — {v.summary[:80]}")
        if v.fixed_version:
            click.echo(f"     Fix: {v.fixed_version}")
