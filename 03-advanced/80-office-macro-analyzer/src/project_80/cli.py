"""Office Macro Risk Analyzer — CLI interface."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import click

from project_80.core import MacroAnalyzer, SUPPORTED_EXTENSIONS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Office Macro Risk Analyzer — VBA macro risk analysis."""


@cli.command("analyze")
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--show-vba", is_flag=True, default=False, help="Print extracted VBA code.")
def analyze_cmd(file: Path, output: Path | None, show_vba: bool) -> None:
    """Analyze an Office document for macro-based threats."""
    analyzer = MacroAnalyzer()
    click.echo(f"Analyzing {file.name} …")
    result = analyzer.analyze(file)

    click.echo(f"\nFile: {result.file_path}")
    click.echo(f"Format: {result.file_format}   Size: {result.file_size:,} bytes")
    click.echo(f"SHA256: {result.sha256}")
    click.echo(f"Has macros: {result.has_macros}")
    click.echo(f"Analysis engine: {'oletools' if result.oletools_available else 'regex fallback'}")

    if result.indicators:
        click.echo(f"\nRisk indicators ({len(result.indicators)}):")
        for ind in result.indicators:
            color = {"LOW": "cyan", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bright_red"}.get(
                ind.severity, "white"
            )
            line = click.style(f"  [{ind.severity}]", fg=color) + f" {ind.description}"
            if ind.mitre_technique:
                line += f" ({ind.mitre_technique})"
            if ind.snippet:
                line += f"\n         snippet: {ind.snippet[:80]}"
            click.echo(line)
    else:
        click.echo("\nNo risk indicators found.")

    color = "green" if result.risk_score < 25 else ("yellow" if result.risk_score < 50 else "red")
    click.echo(f"\nRisk score: " + click.style(str(result.risk_score), fg=color))
    if result.error:
        click.echo(f"Error: {result.error}", err=True)

    if show_vba:
        for i, code in enumerate(result.vba_code):
            click.echo(f"\n--- VBA Module {i + 1} ---")
            click.echo(code[:2000])

    if output:
        output.write_text(json.dumps(result.to_dict(), indent=2))
        click.echo(f"\nReport saved to {output}")


@cli.command("batch")
@click.argument("directory", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", required=True, type=click.Path(path_type=Path))
def batch_cmd(directory: Path, output: Path) -> None:
    """Batch-analyze all Office documents in a directory."""
    analyzer = MacroAnalyzer()
    files = [
        p for p in directory.iterdir()
        if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS
    ]
    click.echo(f"Found {len(files)} Office document(s) to analyze …")
    results = []
    for f in files:
        try:
            result = analyzer.analyze(f)
            results.append(result.to_dict())
            color = "green" if result.risk_score < 25 else ("yellow" if result.risk_score < 50 else "red")
            click.echo(
                f"  {f.name:<45} macros={result.has_macros}  score="
                + click.style(str(result.risk_score), fg=color)
            )
        except OSError as exc:
            click.echo(f"  {f.name}: ERROR — {exc}", err=True)
    output.write_text(json.dumps(results, indent=2))
    click.echo(f"\nBatch report saved to {output}")
