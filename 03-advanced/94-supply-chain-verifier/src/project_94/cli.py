"""Supply Chain Verifier — CLI interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from project_94.core import (
    hash_artifact,
    parse_checksums_file,
    verify_artifact,
    verify_hash,
)


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Supply Chain Verifier — artifact integrity and SLSA provenance verification."""


@cli.command("hash")
@click.argument("artifact", type=click.Path(exists=True, path_type=Path))
@click.option("--algorithm", "-a", default="sha256", show_default=True,
              type=click.Choice(["sha256", "sha512", "sha384", "sha1", "md5"]))
def hash_cmd(artifact: Path, algorithm: str) -> None:
    """Compute and print the hash of an artifact."""
    digest = hash_artifact(artifact, algorithm)
    click.echo(f"{digest}  {artifact.name}")


@cli.command("verify")
@click.argument("artifact", type=click.Path(exists=True, path_type=Path))
@click.option("--expected-hash", "-e", default=None, help="Expected hash digest")
@click.option("--algorithm", "-a", default="sha256", show_default=True)
@click.option("--attestation", type=click.Path(path_type=Path), default=None,
              help="Path to SLSA in-toto attestation JSON")
@click.option("--min-slsa-level", default=0, type=int, show_default=True)
@click.option("--trusted-builder", multiple=True, help="Trusted builder ID prefix (repeatable)")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--exit-code", is_flag=True, default=False)
def verify_cmd(
    artifact: Path,
    expected_hash: str | None,
    algorithm: str,
    attestation: Path | None,
    min_slsa_level: int,
    trusted_builder: tuple[str, ...],
    output: Path | None,
    exit_code: bool,
) -> None:
    """Verify artifact integrity and optional SLSA provenance."""
    result = verify_artifact(
        artifact,
        expected_hash=expected_hash,
        hash_algorithm=algorithm,
        attestation_path=attestation,
        min_slsa_level=min_slsa_level,
        trusted_builders=list(trusted_builder) if trusted_builder else None,
    )
    status = click.style("PASS", fg="green") if result.passed else click.style("FAIL", fg="red")
    click.echo(f"Artifact: {artifact.name}  [{status}]")
    for check in result.checks:
        icon = click.style("✓", fg="green") if check.passed else click.style("✗", fg="red")
        click.echo(f"  {icon} {check.name}: {check.detail}")
    if result.provenance:
        click.echo(f"\nProvenance:")
        click.echo(f"  Builder:    {result.provenance.builder_id}")
        click.echo(f"  SLSA level: {result.provenance.slsa_level}")
        click.echo(f"  Type:       {result.provenance.predicate_type}")

    if output:
        output.write_text(json.dumps(result.to_dict(), indent=2))
        click.echo(f"\nReport saved to {output}")

    if exit_code and not result.passed:
        sys.exit(1)


@cli.command("check-sums")
@click.argument("checksums_file", type=click.Path(exists=True, path_type=Path))
@click.option("--base-dir", type=click.Path(path_type=Path), default=None)
@click.option("--exit-code", is_flag=True, default=False)
def check_sums_cmd(checksums_file: Path, base_dir: Path | None, exit_code: bool) -> None:
    """Verify artifacts listed in a sha256sums-style checksums file."""
    base = base_dir or checksums_file.parent
    entries = parse_checksums_file(checksums_file)
    click.echo(f"Verifying {len(entries)} artifact(s) from {checksums_file.name}")
    all_passed = True
    for entry in entries:
        artifact_path = base / entry.filename
        if not artifact_path.exists():
            click.echo(click.style(f"  MISSING", fg="red") + f"  {entry.filename}")
            all_passed = False
            continue
        ok = verify_hash(artifact_path, entry.digest, entry.algorithm)
        icon = click.style("OK", fg="green") if ok else click.style("FAIL", fg="red")
        click.echo(f"  {icon}  {entry.filename}")
        if not ok:
            all_passed = False
    if exit_code and not all_passed:
        sys.exit(1)
