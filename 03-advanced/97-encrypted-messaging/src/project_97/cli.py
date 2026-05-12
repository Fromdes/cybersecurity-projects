"""Encrypted Messaging Library — CLI demo interface."""

from __future__ import annotations

import click

from project_97.core import create_session_pair


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """Encrypted Messaging Library — Double Ratchet algorithm demo."""


@cli.command("demo")
@click.option("--messages", "-n", default=5, type=int, show_default=True,
              help="Number of messages to exchange")
def demo_cmd(messages: int) -> None:
    """Run a Double Ratchet messaging demo between Alice and Bob."""
    alice, bob = create_session_pair()
    click.echo("=== Double Ratchet Demo ===")
    click.echo("Session established with fresh shared secret.\n")

    for i in range(messages):
        plaintext = f"Message {i + 1} from Alice to Bob"
        wire = alice.send(plaintext)
        decrypted = bob.receive(wire)
        status = click.style("OK", fg="green") if decrypted == plaintext else click.style("FAIL", fg="red")
        click.echo(f"Alice → Bob [{status}]: {decrypted!r}")

    click.echo()
    for i in range(messages):
        plaintext = f"Reply {i + 1} from Bob to Alice"
        wire = bob.send(plaintext)
        decrypted = alice.receive(wire)
        status = click.style("OK", fg="green") if decrypted == plaintext else click.style("FAIL", fg="red")
        click.echo(f"Bob → Alice [{status}]: {decrypted!r}")

    click.echo(f"\n{messages * 2} messages exchanged with forward secrecy.")


@cli.command("test-ratchet")
def test_ratchet_cmd() -> None:
    """Test forward secrecy: decryption fails if a message key is replayed."""
    alice, bob = create_session_pair()
    wire = alice.send("secret message")
    decrypted = bob.receive(wire)
    click.echo(f"First decrypt: {decrypted!r}")
    try:
        bob.receive(wire)
        click.echo(click.style("FAIL: replay was accepted", fg="red"))
    except Exception as e:
        click.echo(click.style(f"OK: replay rejected ({type(e).__name__})", fg="green"))
