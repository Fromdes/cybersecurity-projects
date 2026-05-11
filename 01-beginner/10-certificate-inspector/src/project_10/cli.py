"""CLI for the X.509 Certificate Inspector."""

from __future__ import annotations

import argparse
import json
import ssl
import sys
from pathlib import Path

from project_10.core import (
    CertificateReport,
    inspect_certificate,
    load_from_file,
    load_from_host,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cert-inspect",
        description="Inspect X.509 certificates for expiry, weak keys, and misconfigurations.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # file subcommand
    f = sub.add_parser("file", help="Inspect a certificate file (PEM or DER)")
    f.add_argument("path", type=Path, help="Certificate file path")
    f.add_argument("--json", action="store_true", dest="as_json")

    # host subcommand
    h = sub.add_parser("host", help="Inspect the live TLS certificate of a host")
    h.add_argument("host", help="Hostname (e.g. example.com)")
    h.add_argument("--port", type=int, default=443)
    h.add_argument("--json", action="store_true", dest="as_json")
    h.add_argument("--timeout", type=int, default=10)

    return parser


def _format_report(report: CertificateReport, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps({
            "subject": report.subject,
            "issuer": report.issuer,
            "serial_number": report.serial_number,
            "not_before": report.not_before.isoformat(),
            "not_after": report.not_after.isoformat(),
            "days_until_expiry": report.days_until_expiry,
            "expiry_status": report.expiry_status,
            "key_type": report.key_type,
            "key_bits": report.key_bits,
            "signature_algorithm": report.signature_algorithm,
            "subject_alt_names": report.subject_alt_names,
            "is_self_signed": report.is_self_signed,
            "warnings": report.warnings,
        }, indent=2, default=str))
        return

    status_symbol = {
        "valid": "[OK]",
        "warning": "[WARN]",
        "critical": "[CRIT]",
        "expired": "[EXPIRED]",
    }.get(report.expiry_status, "[?]")

    print(f"Subject          : {report.subject}")
    print(f"Issuer           : {report.issuer}")
    print(f"Serial           : {report.serial_number}")
    print(f"Valid from       : {report.not_before.strftime('%Y-%m-%d')}")
    print(f"Valid until      : {report.not_after.strftime('%Y-%m-%d')}  {status_symbol}")
    print(f"Days remaining   : {report.days_until_expiry}")
    print(f"Key              : {report.key_type}-{report.key_bits}")
    print(f"Signature alg    : {report.signature_algorithm}")
    if report.subject_alt_names:
        print(f"SANs             : {', '.join(report.subject_alt_names[:5])}", end="")
        if len(report.subject_alt_names) > 5:
            print(f" (+{len(report.subject_alt_names) - 5} more)", end="")
        print()
    if report.is_self_signed:
        print("Self-signed      : YES")
    if report.warnings:
        print("\nWarnings:")
        for w in report.warnings:
            print(f"  ! {w}")


def _cmd_file(args: argparse.Namespace) -> int:
    try:
        cert = load_from_file(args.path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    report = inspect_certificate(cert)
    _format_report(report, as_json=args.as_json)
    return 0 if not report.warnings else 1


def _cmd_host(args: argparse.Namespace) -> int:
    try:
        cert = load_from_host(args.host, args.port, timeout=args.timeout)
    except (ConnectionError, ValueError, ssl.SSLError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    report = inspect_certificate(cert)
    _format_report(report, as_json=args.as_json)
    return 0 if not report.warnings else 1


def main() -> None:
    """Entry point for the cert-inspect CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    dispatch = {"file": _cmd_file, "host": _cmd_host}
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    sys.exit(handler(args))
