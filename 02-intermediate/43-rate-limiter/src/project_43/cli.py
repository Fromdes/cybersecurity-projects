"""CLI interface for Rate Limiter."""

from __future__ import annotations

import json
import time

import click

from project_43.core import (
    FixedWindowLimiter,
    LimitResult,
    SlidingWindowLimiter,
    TokenBucketLimiter,
)

_ALGORITHMS = {
    "token-bucket": "Token Bucket (burst-friendly, continuous refill)",
    "sliding-window": "Sliding Window Log (precise, per-request timestamps)",
    "fixed-window": "Fixed Window Counter (simple, boundary-burst risk)",
}


@click.group()
def main() -> None:
    """Rate Limiter — token bucket, sliding window, and fixed window algorithms."""


@main.command("demo")
@click.option("--algo", default="token-bucket",
              type=click.Choice(["token-bucket", "sliding-window", "fixed-window"]),
              show_default=True, help="Algorithm to demo")
@click.option("--requests", "n_requests", default=12, show_default=True)
@click.option("--limit", default=5, show_default=True)
@click.option("--window", default=2.0, show_default=True, help="Window/refill seconds")
def cmd_demo(algo: str, n_requests: int, limit: int, window: float) -> None:
    """Simulate a burst of requests and show allow/deny decisions."""
    click.echo(f"Algorithm  : {_ALGORITHMS[algo]}")
    click.echo(f"Limit      : {limit} req / {window}s window\n")

    if algo == "token-bucket":
        limiter = TokenBucketLimiter(capacity=limit, rate=limit / window)
    elif algo == "sliding-window":
        limiter = SlidingWindowLimiter(limit=limit, window_seconds=window)
    else:
        limiter = FixedWindowLimiter(limit=limit, window_seconds=window)

    key = "demo-user"
    for i in range(1, n_requests + 1):
        decision = limiter.check(key)
        color = "green" if decision.allowed else "red"
        verdict = "ALLOW" if decision.allowed else "DENY "
        click.echo(
            click.style(f"  Req {i:02d}: {verdict}", fg=color)
            + f"  remaining={decision.remaining}  retry_after={decision.retry_after:.2f}s"
        )

    click.echo(click.style(f"\nDone. {n_requests} requests sent.", bold=True))


@main.command("check")
@click.option("--key", required=True, help="Rate limit key (user ID, IP, etc.)")
@click.option("--limit", default=10, show_default=True)
@click.option("--window", default=60.0, show_default=True)
@click.option("--algo", default="sliding-window",
              type=click.Choice(["token-bucket", "sliding-window", "fixed-window"]),
              show_default=True)
@click.option("--json", "output_json", is_flag=True)
def cmd_check(key: str, limit: int, window: float, algo: str, output_json: bool) -> None:
    """Perform one rate-limit check for a key (in-process demo store)."""
    if algo == "token-bucket":
        limiter = TokenBucketLimiter(capacity=limit, rate=limit / window)
    elif algo == "sliding-window":
        limiter = SlidingWindowLimiter(limit=limit, window_seconds=window)
    else:
        limiter = FixedWindowLimiter(limit=limit, window_seconds=window)

    decision = limiter.check(key)
    if output_json:
        click.echo(json.dumps({
            "result": decision.result.value,
            "allowed": decision.allowed,
            "remaining": decision.remaining,
            "retry_after": decision.retry_after,
        }, indent=2))
    else:
        color = "green" if decision.allowed else "red"
        click.echo(click.style(decision.result.value.upper(), fg=color, bold=True))
        click.echo(f"Remaining  : {decision.remaining}")
        click.echo(f"Retry after: {decision.retry_after:.2f}s")


@main.command("compare")
@click.option("--limit", default=5, show_default=True)
@click.option("--window", default=2.0, show_default=True)
@click.option("--requests", "n_requests", default=8, show_default=True)
def cmd_compare(limit: int, window: float, n_requests: int) -> None:
    """Compare all three algorithms side by side."""
    limiters = {
        "TokenBucket  ": TokenBucketLimiter(capacity=limit, rate=limit / window),
        "SlidingWindow": SlidingWindowLimiter(limit=limit, window_seconds=window),
        "FixedWindow  ": FixedWindowLimiter(limit=limit, window_seconds=window),
    }
    click.echo(f"{'Req':>4}  " + "  ".join(limiters.keys()))
    for i in range(1, n_requests + 1):
        row = f" {i:02d}   "
        for name, lim in limiters.items():
            d = lim.check("u")
            symbol = click.style("A", fg="green") if d.allowed else click.style("D", fg="red")
            row += f"  {symbol}{'':12}"
        click.echo(row)
