"""TLS handshake inspection using the Python standard ssl module."""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

CONNECT_TIMEOUT: float = 10.0
DEFAULT_PORT: int = 443
CERT_DATE_FORMAT: str = "%b %d %H:%M:%S %Y %Z"


@dataclass(frozen=True)
class CertInfo:
    """Parsed X.509 certificate metadata."""

    subject: dict[str, str]
    issuer: dict[str, str]
    serial_number: str
    not_before: datetime
    not_after: datetime
    san: list[str]
    is_expired: bool
    days_until_expiry: int


@dataclass(frozen=True)
class TLSResult:
    """Result of a TLS handshake inspection."""

    host: str
    port: int
    protocol_version: str
    cipher_name: str
    cipher_bits: int
    cert: CertInfo
    tls_ok: bool


def inspect_host(host: str, port: int = DEFAULT_PORT) -> TLSResult:
    """Perform a TLS handshake against *host*:*port* and return inspection data.

    Args:
        host: Hostname or IP address to connect to.
        port: TCP port (default: 443).

    Returns:
        TLSResult with protocol, cipher, and certificate details.

    Raises:
        ValueError: If host is empty.
        OSError: On network or TLS connection errors.
        ssl.SSLCertVerificationError: If certificate validation fails.
    """
    if not host.strip():
        raise ValueError("host must not be empty")
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as conn:
            return _extract_result(host, port, conn)


def _extract_result(host: str, port: int, conn: ssl.SSLSocket) -> TLSResult:
    cipher = conn.cipher()
    cipher_name = cipher[0] if cipher else "unknown"
    cipher_bits = int(cipher[2]) if cipher and cipher[2] else 0
    proto = conn.version() or "unknown"
    raw_cert: dict[str, object] = conn.getpeercert() or {}
    cert = _parse_cert(raw_cert)
    return TLSResult(
        host=host, port=port,
        protocol_version=proto, cipher_name=cipher_name, cipher_bits=cipher_bits,
        cert=cert, tls_ok=not cert.is_expired,
    )


def _parse_cert(raw: dict[str, object]) -> CertInfo:
    subject = _rdn_to_dict(raw.get("subject", ()))  # type: ignore[arg-type]
    issuer = _rdn_to_dict(raw.get("issuer", ()))  # type: ignore[arg-type]
    serial = str(raw.get("serialNumber", ""))
    not_before = _parse_date(str(raw.get("notBefore", "")))
    not_after = _parse_date(str(raw.get("notAfter", "")))
    san = _extract_san(raw.get("subjectAltName", ()))  # type: ignore[arg-type]
    now = datetime.now(tz=timezone.utc)
    _epoch = datetime.min.replace(tzinfo=timezone.utc)
    nb = not_before or _epoch
    na = not_after or _epoch
    is_expired = (na < now) if not_after else False
    days = (na - now).days if not_after else 0
    return CertInfo(
        subject=subject, issuer=issuer, serial_number=serial,
        not_before=nb, not_after=na, san=san,
        is_expired=is_expired, days_until_expiry=days,
    )


def _rdn_to_dict(rdn_seq: tuple[tuple[tuple[str, str], ...], ...]) -> dict[str, str]:
    result: dict[str, str] = {}
    for rdn in rdn_seq:
        for attr, value in rdn:
            result[attr] = value
    return result


def _parse_date(date_str: str) -> datetime | None:
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _extract_san(san_seq: tuple[tuple[str, str], ...]) -> list[str]:
    return [f"{typ}:{val}" for typ, val in san_seq]
