"""Behavioral Authentication — CLI interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from project_96.core import (
    build_profile,
    generate_synthetic_sample,
    load_profile,
    save_profile,
    verify_sample,
)


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Behavioral Authentication PoC — keystroke dynamics profiling."""


@cli.command("enroll")
@click.option("--user", "-u", required=True, help="User ID to enroll")
@click.option("--samples-file", "-s", type=click.Path(exists=True, path_type=Path),
              default=None, help="JSONL file of keystroke samples")
@click.option("--profile-dir", type=click.Path(path_type=Path), default=Path("."),
              show_default=True)
@click.option("--threshold", default=2.5, type=float, show_default=True)
def enroll_cmd(user: str, samples_file: Path | None, profile_dir: Path, threshold: float) -> None:
    """Enroll a user by building a behavioral profile from keystroke samples."""
    if samples_file:
        raw_samples = [json.loads(l) for l in samples_file.read_text().splitlines() if l.strip()]
        samples = [_dict_to_sample(s) for s in raw_samples]
    else:
        # Generate synthetic demo samples
        passphrase = "security"
        keys = list(passphrase)
        click.echo(f"Generating synthetic enrollment samples for demo (passphrase: {passphrase!r})")
        samples = [generate_synthetic_sample(keys) for _ in range(10)]

    passphrase = "security" if not samples_file else "custom"
    profile = build_profile(user, passphrase, samples, threshold=threshold)
    profile_path = Path(profile_dir) / f"{user}.profile.json"
    save_profile(profile, profile_path)
    click.echo(f"Enrolled {user} with {len(samples)} samples.")
    click.echo(f"Profile saved to {profile_path}")
    click.echo(f"Threshold: {threshold}")


@cli.command("verify")
@click.option("--user", "-u", required=True, help="User ID to verify")
@click.option("--sample-file", "-s", type=click.Path(exists=True, path_type=Path),
              default=None, help="JSON file of a single keystroke sample")
@click.option("--profile-dir", type=click.Path(path_type=Path), default=Path("."),
              show_default=True)
@click.option("--exit-code", is_flag=True, default=False)
def verify_cmd(user: str, sample_file: Path | None, profile_dir: Path, exit_code: bool) -> None:
    """Verify a keystroke sample against an enrolled profile."""
    profile_path = Path(profile_dir) / f"{user}.profile.json"
    if not profile_path.exists():
        click.echo(f"No profile found for user {user!r} at {profile_path}", err=True)
        sys.exit(2)

    profile = load_profile(profile_path)

    if sample_file:
        data = json.loads(sample_file.read_text())
        sample = _dict_to_sample(data)
    else:
        keys = list(profile.passphrase)
        click.echo("Generating synthetic verification sample for demo")
        sample = generate_synthetic_sample(keys)

    result = verify_sample(profile, sample)
    status = click.style("ACCEPTED", fg="green") if result.accepted else click.style("REJECTED", fg="red")
    click.echo(f"User: {user}  [{status}]")
    click.echo(f"  Score (mean z): {result.score:.4f}  (threshold: {result.threshold})")

    if exit_code and not result.accepted:
        sys.exit(1)


@cli.command("demo")
@click.option("--user", default="demo-user", show_default=True)
def demo_cmd(user: str) -> None:
    """Run a self-contained enrollment + verification demo."""

    passphrase = "security"
    keys = list(passphrase)
    click.echo("=== Behavioral Auth Demo ===")
    click.echo(f"Passphrase: {passphrase!r}")

    click.echo("\n[1] Enrolling with 10 consistent samples...")
    enroll_samples = [generate_synthetic_sample(keys, mean_dwell=0.08, mean_flight=0.12, noise=0.01)
                      for _ in range(10)]
    profile = build_profile(user, passphrase, enroll_samples)

    click.echo("[2] Verifying with a matching sample (same timing pattern)...")
    good_sample = generate_synthetic_sample(keys, mean_dwell=0.08, mean_flight=0.12, noise=0.015)
    r1 = verify_sample(profile, good_sample)
    s1 = click.style("ACCEPTED", fg="green") if r1.accepted else click.style("REJECTED", fg="red")
    click.echo(f"    Legitimate user: [{s1}] score={r1.score:.3f}")

    click.echo("[3] Verifying with an impostor (very different timing)...")
    bad_sample = generate_synthetic_sample(keys, mean_dwell=0.25, mean_flight=0.40, noise=0.05)
    r2 = verify_sample(profile, bad_sample)
    s2 = click.style("ACCEPTED", fg="green") if r2.accepted else click.style("REJECTED", fg="red")
    click.echo(f"    Impostor:         [{s2}] score={r2.score:.3f}")


def _dict_to_sample(data: dict):  # type: ignore[type-arg]
    from project_96.core import KeystrokeSample
    return KeystrokeSample(
        dwell_times=data.get("dwell_times", {}),
        flight_times=data.get("flight_times", []),
        digraph_times=data.get("digraph_times", {}),
    )
