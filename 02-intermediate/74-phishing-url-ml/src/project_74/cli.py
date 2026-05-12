"""CLI for Phishing URL ML Detector."""

from __future__ import annotations

import sys

import click

from project_74.core import PhishingURLClassifier, extract_features, heuristic_classify


@click.group()
def cli() -> None:
    """Phishing URL ML Detector — classify URLs as phishing or legitimate."""


@cli.command()
@click.argument("url")
def check(url: str) -> None:
    """Check a single URL."""
    clf = PhishingURLClassifier()
    pred = clf.predict(url)
    verdict = "PHISHING" if pred.is_phishing else "CLEAN"
    click.echo(f"\n[{verdict}] {url}")
    click.echo(f"  Confidence: {pred.confidence:.2f}")
    click.echo(f"  Reason    : {pred.reason}")


@cli.command()
@click.argument("urls_file", type=click.Path(exists=True))
def scan(urls_file: str) -> None:
    """Scan each URL in URLS_FILE (one per line)."""
    clf = PhishingURLClassifier()
    with open(urls_file) as fh:
        urls = [line.strip() for line in fh if line.strip()]
    preds = clf.predict_batch(urls)
    phishing = [p for p in preds if p.is_phishing]
    click.echo(f"Scanned {len(preds)} URLs — {len(phishing)} flagged as phishing\n")
    for p in preds:
        verdict = "PHISH" if p.is_phishing else "clean"
        click.echo(f"  [{verdict}] {p.url[:60]}  ({p.confidence:.2f})")
