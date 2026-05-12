"""Zero Trust Network Gateway — CLI interface."""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

import click

from project_93.core import (
    AccessRequest,
    AuditLog,
    load_policy_file,
)


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Zero Trust Network Gateway — policy-based access control with audit logging."""


@cli.command("check")
@click.option("--policy", "-p", required=True, type=click.Path(exists=True, path_type=Path),
              help="Path to Zero Trust policy JSON file")
@click.option("--principal", required=True, help="Identity making the request (user/service)")
@click.option("--source-ip", required=True, help="Source IP address")
@click.option("--destination", required=True, help="Destination hostname or IP")
@click.option("--port", required=True, type=int, help="Destination port")
@click.option("--protocol", default="tcp", show_default=True, help="Network protocol")
@click.option("--mfa", is_flag=True, default=False, help="MFA was verified")
@click.option("--risk-score", default=0, type=int, show_default=True, help="Pre-computed risk score")
def check_cmd(
    policy: Path,
    principal: str,
    source_ip: str,
    destination: str,
    port: int,
    protocol: str,
    mfa: bool,
    risk_score: int,
) -> None:
    """Evaluate a single access request against a Zero Trust policy."""
    zt_policy = load_policy_file(policy)
    request = AccessRequest(
        request_id=str(uuid.uuid4()),
        principal=principal,
        source_ip=source_ip,
        destination=destination,
        port=port,
        protocol=protocol,
        mfa_verified=mfa,
        risk_score=risk_score,
    )
    decision = zt_policy.evaluate(request)
    status = click.style("ALLOW", fg="green") if decision.allowed else click.style("DENY", fg="red")
    click.echo(f"Decision: {status}")
    click.echo(f"  Reason: {decision.reason}")
    click.echo(f"  Request ID: {decision.request_id}")
    if not decision.allowed:
        sys.exit(1)


@cli.command("evaluate")
@click.option("--policy", "-p", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--requests", "-r", required=True, type=click.Path(exists=True, path_type=Path),
              help="JSONL file of access requests")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def evaluate_cmd(policy: Path, requests: Path, output: Path | None) -> None:
    """Batch-evaluate access requests from a JSONL file."""
    zt_policy = load_policy_file(policy)
    log = AuditLog()
    lines = requests.read_text().splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        data = json.loads(line)
        request = AccessRequest(
            request_id=data.get("request_id", str(uuid.uuid4())),
            principal=data["principal"],
            source_ip=data["source_ip"],
            destination=data["destination"],
            port=int(data["port"]),
            protocol=data.get("protocol", "tcp"),
            mfa_verified=data.get("mfa_verified", False),
            risk_score=data.get("risk_score", 0),
        )
        decision = zt_policy.evaluate(request)
        log.record(request, decision)
        symbol = click.style("✓", fg="green") if decision.allowed else click.style("✗", fg="red")
        click.echo(f"{symbol} {request.principal}@{request.source_ip} → {request.destination}:{request.port} — {decision.reason}")

    click.echo(f"\nSummary: {log.allowed_count()} allowed, {log.denied_count()} denied")
    if output:
        output.write_text(log.to_jsonl())
        click.echo(f"Audit log saved to {output}")
