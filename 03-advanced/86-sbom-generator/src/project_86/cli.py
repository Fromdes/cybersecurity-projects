"""SBOM Generator — CLI interface."""

from __future__ import annotations

import json
from pathlib import Path

import click

from project_86.core import SBOMDocument, detect_and_parse


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """SBOM Generator — produce CycloneDX / SPDX Software Bills of Materials."""


@cli.command("generate")
@click.argument("manifest", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "fmt", default="cyclonedx",
              type=click.Choice(["cyclonedx", "spdx"]), show_default=True)
@click.option("--output", "-o", required=True, type=click.Path(path_type=Path))
def generate_cmd(manifest: Path, fmt: str, output: Path) -> None:
    """Generate an SBOM from a dependency manifest."""
    components = detect_and_parse(manifest)
    doc = SBOMDocument.from_components(components, source=manifest.name)
    if fmt == "cyclonedx":
        data = doc.to_cyclonedx()
    else:
        data = doc.to_spdx()
    output.write_text(json.dumps(data, indent=2))
    summary = doc.summary()
    click.echo(f"SBOM generated: {summary['total_components']} component(s) → {output}")
    for eco, cnt in summary["by_ecosystem"].items():
        click.echo(f"  {eco}: {cnt}")


@cli.command("summary")
@click.argument("sbom_file", type=click.Path(exists=True, path_type=Path))
def summary_cmd(sbom_file: Path) -> None:
    """Print summary of an existing CycloneDX SBOM file."""
    data = json.loads(sbom_file.read_text())
    fmt = data.get("bomFormat", data.get("spdxVersion", "unknown"))
    components = data.get("components", data.get("packages", []))
    click.echo(f"Format: {fmt}")
    click.echo(f"Components: {len(components)}")
    for comp in components[:10]:
        name = comp.get("name", "?")
        version = comp.get("version", comp.get("versionInfo", "?"))
        click.echo(f"  {name}@{version}")
    if len(components) > 10:
        click.echo(f"  … and {len(components) - 10} more")
