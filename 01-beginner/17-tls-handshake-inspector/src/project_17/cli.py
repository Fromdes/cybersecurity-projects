"""CLI for the TLS Handshake Inspector."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from project_17.core import TLSResult, inspect_host


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tls-inspect",
        description="Inspect TLS handshake, cipher suite, and certificate for a host",
    )
    parser.add_argument("host", help="Hostname or IP address to connect to")
    parser.add_argument(
        "--port", "-p", type=int, default=443, metavar="PORT",
        help="TCP port (default: 443)",
    )
    parser.add_argument(
        "--json", "-j", action="store_true", dest="json_out",
        help="Output as JSON",
    )
    return parser


def _result_to_dict(result: TLSResult) -> dict[str, Any]:
    cert = result.cert
    return {
        "host": result.host,
        "port": result.port,
        "protocol_version": result.protocol_version,
        "cipher_name": result.cipher_name,
        "cipher_bits": result.cipher_bits,
        "tls_ok": result.tls_ok,
        "certificate": {
            "subject": cert.subject,
            "issuer": cert.issuer,
            "serial_number": cert.serial_number,
            "not_before": cert.not_before.isoformat(),
            "not_after": cert.not_after.isoformat(),
            "san": cert.san,
            "is_expired": cert.is_expired,
            "days_until_expiry": cert.days_until_expiry,
        },
    }


def _print_human(result: TLSResult) -> None:
    cert = result.cert
    status = "EXPIRED" if cert.is_expired else f"OK (expires in {cert.days_until_expiry}d)"
    print(f"Host          : {result.host}:{result.port}")
    print(f"Protocol      : {result.protocol_version}")
    print(f"Cipher        : {result.cipher_name} ({result.cipher_bits} bits)")
    print(f"Subject       : {cert.subject}")
    print(f"Issuer        : {cert.issuer}")
    print(f"Serial        : {cert.serial_number}")
    print(f"Not Before    : {cert.not_before.isoformat()}")
    print(f"Not After     : {cert.not_after.isoformat()}")
    print(f"SANs          : {', '.join(cert.san) or 'none'}")
    print(f"Certificate   : {status}")


def main() -> None:
    """Entry point for the TLS handshake inspector CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    try:
        result = inspect_host(args.host, args.port)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    if args.json_out:
        print(json.dumps(_result_to_dict(result), indent=2))
    else:
        _print_human(result)
