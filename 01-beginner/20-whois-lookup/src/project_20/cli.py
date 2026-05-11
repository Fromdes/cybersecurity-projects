"""CLI for the WHOIS Lookup Wrapper."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from project_20.core import WhoisResult, lookup


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="whois-lookup",
        description="Query WHOIS registration data for domains and IP addresses",
    )
    parser.add_argument("query", help="Domain name or IP address to look up")
    parser.add_argument(
        "--json", "-j", action="store_true", dest="json_out",
        help="Output as JSON",
    )
    return parser


def _result_to_dict(result: WhoisResult) -> dict[str, Any]:
    return {
        "query": result.query,
        "registrar": result.registrar,
        "creation_date": result.creation_date.isoformat() if result.creation_date else None,
        "expiration_date": result.expiration_date.isoformat() if result.expiration_date else None,
        "updated_date": result.updated_date.isoformat() if result.updated_date else None,
        "name_servers": list(result.name_servers),
        "status": list(result.status),
        "emails": list(result.emails),
        "country": result.country,
        "dnssec": result.dnssec,
    }


def _print_human(result: WhoisResult) -> None:
    def fmt_date(dt: Any) -> str:
        return dt.strftime("%Y-%m-%d") if dt else "N/A"

    print(f"Query         : {result.query}")
    print(f"Registrar     : {result.registrar or 'N/A'}")
    print(f"Created       : {fmt_date(result.creation_date)}")
    print(f"Expires       : {fmt_date(result.expiration_date)}")
    print(f"Updated       : {fmt_date(result.updated_date)}")
    print(f"Name Servers  : {', '.join(result.name_servers) or 'N/A'}")
    print(f"Status        : {', '.join(result.status) or 'N/A'}")
    print(f"Emails        : {', '.join(result.emails) or 'N/A'}")
    print(f"Country       : {result.country or 'N/A'}")
    print(f"DNSSEC        : {result.dnssec or 'N/A'}")


def main() -> None:
    """Entry point for the WHOIS lookup CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    try:
        result = lookup(args.query)
    except (ValueError, Exception) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    if args.json_out:
        print(json.dumps(_result_to_dict(result), indent=2))
    else:
        _print_human(result)
