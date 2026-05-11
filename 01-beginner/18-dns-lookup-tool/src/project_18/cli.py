"""CLI for the DNS Lookup & Reverse DNS Tool."""
from __future__ import annotations

import argparse
import sys

import dns.exception

from project_18.core import DNSRecord, RecordType, lookup, reverse_lookup


def _add_lookup_cmd(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    p = sub.add_parser("lookup", help="Query DNS records for a hostname")
    p.add_argument("hostname", help="Domain name to resolve")
    p.add_argument(
        "--type", "-t", dest="record_type",
        choices=[r.value for r in RecordType if r is not RecordType.PTR],
        default=RecordType.A.value,
        help="Record type (default: A)",
    )
    p.add_argument("--timeout", type=float, default=5.0, help="Query timeout (default: 5s)")


def _add_reverse_cmd(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    p = sub.add_parser("reverse", help="Reverse DNS lookup for an IP address")
    p.add_argument("ip", help="IPv4 or IPv6 address")
    p.add_argument("--timeout", type=float, default=5.0, help="Query timeout (default: 5s)")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dns-lookup",
        description="Query DNS records and reverse-resolve IP addresses",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    _add_lookup_cmd(sub)
    _add_reverse_cmd(sub)
    return parser


def _print_records(records: list[DNSRecord]) -> None:
    for rec in records:
        print(f"{rec.name:<40} {rec.record_type.value:<6} {rec.ttl:>6}s  {rec.value}")


def _cmd_lookup(args: argparse.Namespace) -> None:
    records = lookup(args.hostname, RecordType(args.record_type), timeout=args.timeout)
    if not records:
        print(f"No {args.record_type} records found for {args.hostname}")
        return
    _print_records(records)


def _cmd_reverse(args: argparse.Namespace) -> None:
    records = reverse_lookup(args.ip, timeout=args.timeout)
    if not records:
        print(f"No PTR records found for {args.ip}")
        return
    _print_records(records)


def main() -> None:
    """Entry point for the DNS lookup CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    try:
        if args.command == "lookup":
            _cmd_lookup(args)
        elif args.command == "reverse":
            _cmd_reverse(args)
    except (ValueError, dns.exception.DNSException) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
