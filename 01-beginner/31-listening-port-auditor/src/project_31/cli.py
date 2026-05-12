"""CLI for the Listening Port Auditor."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from project_31.core import PortEntry, filter_by_risk, list_listening_ports


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port-auditor",
        description="Enumerate and risk-score all listening TCP/UDP ports",
    )
    parser.add_argument(
        "--protocol", choices=["tcp", "udp", "all"], default="all",
        help="Which protocol family to audit (default: all)",
    )
    parser.add_argument(
        "--min-risk", choices=["LOW", "MEDIUM", "HIGH"], default="LOW",
        help="Minimum risk level to display (default: LOW)",
    )
    parser.add_argument(
        "--json", "-j", action="store_true", dest="json_out",
        help="Output as JSON",
    )
    return parser


def _entry_to_dict(e: PortEntry) -> dict[str, Any]:
    return {
        "port": e.port,
        "protocol": e.protocol,
        "local_address": e.local_address,
        "pid": e.pid,
        "process_name": e.process_name,
        "username": e.username,
        "service_guess": e.service_guess,
        "risk_score": e.risk_score,
        "risk_level": e.risk_level,
        "risk_flags": list(e.risk_flags),
    }


def _print_human(entries: list[PortEntry]) -> None:
    if not entries:
        print("No listening ports found matching criteria.")
        return
    print(f"{'PORT':<8} {'PROTO':<5} {'ADDRESS':<20} {'PROCESS':<20} {'RISK':<7} FLAGS")
    print("-" * 90)
    for e in entries:
        flags_str = "; ".join(e.risk_flags) if e.risk_flags else "-"
        print(
            f"{e.port:<8} {e.protocol:<5} {e.local_address:<20} "
            f"{e.process_name[:19]:<20} {e.risk_level:<7} {flags_str}"
        )


def main() -> None:
    """Entry point for the Listening Port Auditor CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    try:
        entries = list_listening_ports(protocol=args.protocol)
        filtered = filter_by_risk(entries, min_level=args.min_risk)
    except PermissionError as exc:
        print(f"Permission denied — try running with sudo: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.json_out:
        print(json.dumps([_entry_to_dict(e) for e in filtered], indent=2))
    else:
        _print_human(filtered)
