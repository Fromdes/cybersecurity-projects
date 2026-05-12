"""Network ML Anomaly Detector — CLI interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from project_98.core import AnomalyReport, analyze_flows, load_flows


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Network ML Anomaly Detector — statistical analysis of network flows."""


@cli.command("analyze")
@click.argument("flows_file", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--z-threshold", default=3.0, type=float, show_default=True)
@click.option("--port-scan-threshold", default=15, type=int, show_default=True)
@click.option("--ddos-threshold", default=20, type=int, show_default=True)
@click.option("--exit-code", is_flag=True, default=False)
@click.option("--min-severity", default="MEDIUM", show_default=True,
              type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]))
def analyze_cmd(
    flows_file: Path,
    output: Path | None,
    z_threshold: float,
    port_scan_threshold: int,
    ddos_threshold: int,
    exit_code: bool,
    min_severity: str,
) -> None:
    """Analyze a network flow file (CSV or JSONL) for anomalies."""
    flows = load_flows(flows_file)
    report = analyze_flows(
        flows,
        z_threshold=z_threshold,
        port_scan_threshold=port_scan_threshold,
        ddos_threshold=ddos_threshold,
        source=str(flows_file),
    )
    click.echo(f"Analyzed {report.flows_analyzed} flows from {flows_file.name}")
    click.echo(f"Anomalies: {len(report.anomalies)}")

    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threshold = order.index(min_severity)
    colors = {"LOW": "cyan", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bright_red"}

    for a in report.anomalies:
        if a.severity in order and order.index(a.severity) >= threshold:
            click.echo(
                click.style(f"  [{a.severity}]", fg=colors.get(a.severity, "white"))
                + f" {a.anomaly_type} — {a.description}"
            )
            click.echo(f"    {a.src_ip} → {a.dst_ip}:{a.dst_port}  [{a.mitre_technique}]")

    if output:
        output.write_text(json.dumps(report.to_dict(), indent=2))
        click.echo(f"\nReport saved to {output}")

    if exit_code and any(a.severity in ("CRITICAL", "HIGH") for a in report.anomalies):
        sys.exit(1)
