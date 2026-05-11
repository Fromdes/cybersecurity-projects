"""CLI for the IP Geolocation & ASN Lookup tool."""
from __future__ import annotations

import argparse
import json
import sys

import requests

from project_19.core import GeoResult, lookup_ip


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ip-geo",
        description="Geolocate IP addresses and identify network ownership (ASN)",
    )
    parser.add_argument(
        "ip",
        nargs="?",
        default="me",
        help="IPv4/IPv6 address to look up (default: your own IP)",
    )
    parser.add_argument(
        "--json", "-j", action="store_true", dest="json_out",
        help="Output as JSON",
    )
    parser.add_argument(
        "--file", "-f", metavar="FILE",
        help="File containing one IP per line for bulk lookup",
    )
    return parser


def _print_human(result: GeoResult) -> None:
    proxy_flag = " [PROXY/VPN]" if result.is_proxy else ""
    hosting_flag = " [HOSTING/DC]" if result.is_hosting else ""
    print(f"IP            : {result.ip}{proxy_flag}{hosting_flag}")
    print(f"Country       : {result.country} ({result.country_code})")
    print(f"Region / City : {result.region}, {result.city}")
    print(f"Coordinates   : {result.latitude}, {result.longitude}")
    print(f"ISP           : {result.isp}")
    print(f"Organisation  : {result.org}")
    print(f"ASN           : {result.asn}")
    print(f"Timezone      : {result.timezone}")


def _process_single(ip: str, json_out: bool) -> int:
    try:
        result = lookup_ip(ip)
    except (ValueError, RuntimeError, requests.RequestException) as exc:
        print(f"Error [{ip}]: {exc}", file=sys.stderr)
        return 1
    if json_out:
        import dataclasses
        print(json.dumps(dataclasses.asdict(result), indent=2))
    else:
        _print_human(result)
    return 0


def _process_file(path: str, json_out: bool) -> int:
    try:
        with open(path, encoding="utf-8") as fh:
            ips = [line.strip() for line in fh if line.strip()]
    except OSError as exc:
        print(f"Error reading file: {exc}", file=sys.stderr)
        return 1
    exit_code = 0
    for ip in ips:
        exit_code |= _process_single(ip, json_out)
        print()
    return exit_code


def main() -> None:
    """Entry point for the IP geolocation CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    if args.file:
        code = _process_file(args.file, args.json_out)
    else:
        code = _process_single(args.ip, args.json_out)
    if code != 0:
        sys.exit(code)
