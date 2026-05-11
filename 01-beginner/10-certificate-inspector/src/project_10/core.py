"""X.509 certificate inspection: expiry, key strength, SANs, and algorithm checks."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.x509.oid import NameOID

# Thresholds for expiry warnings
WARNING_DAYS: int = 30
CRITICAL_DAYS: int = 7

# Minimum acceptable key sizes
MIN_RSA_BITS: int = 2048
MIN_EC_BITS: int = 224  # P-224 is the minimum recommended EC curve

# Weak signature algorithms (hash component)
_WEAK_HASH_OIDS: frozenset[str] = frozenset({"1.2.840.113549.1.1.5"})  # sha1WithRSAEncryption

ExpiryStatus = Literal["valid", "warning", "critical", "expired"]


@dataclass(frozen=True)
class CertificateReport:
    """Full inspection report for a single X.509 certificate."""

    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    days_until_expiry: int
    expiry_status: ExpiryStatus
    key_type: str
    key_bits: int
    signature_algorithm: str
    subject_alt_names: list[str] = field(default_factory=list)
    is_self_signed: bool = False
    warnings: list[str] = field(default_factory=list)


def load_from_file(path: Path) -> x509.Certificate:
    """Load an X.509 certificate from a PEM or DER file.

    Args:
        path: Path to a certificate file (.pem, .crt, .cer, .der).

    Returns:
        Parsed :class:`~cryptography.x509.Certificate`.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError: If the file cannot be parsed as a certificate.
    """
    if not path.exists():
        raise FileNotFoundError(f"Certificate file not found: {path}")
    data = path.read_bytes()
    try:
        return x509.load_pem_x509_certificate(data)
    except (ValueError, TypeError):
        pass
    try:
        return x509.load_der_x509_certificate(data)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Cannot parse certificate from {path}: {exc}") from exc


def load_from_host(host: str, port: int = 443, *, timeout: int = 10) -> x509.Certificate:
    """Retrieve the TLS leaf certificate from a live host.

    Args:
        host: Hostname or IP address.
        port: TCP port (default: 443).
        timeout: Connection timeout in seconds.

    Returns:
        The server's leaf certificate.

    Raises:
        ConnectionError: If the connection fails.
        ssl.SSLError: If TLS negotiation fails.
        ValueError: If the server did not present a certificate.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
    except (OSError, socket.timeout) as exc:
        raise ConnectionError(f"Cannot connect to {host}:{port}: {exc}") from exc
    if not der:
        raise ValueError(f"No certificate received from {host}:{port}")
    return x509.load_der_x509_certificate(der)


def inspect_certificate(cert: x509.Certificate) -> CertificateReport:
    """Produce a :class:`CertificateReport` from a parsed certificate.

    Args:
        cert: A parsed X.509 certificate.

    Returns:
        Structured inspection report with warnings for any detected issues.
    """
    now = datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    days_left = (not_after - now).days
    expiry_status = _classify_expiry(days_left)

    key_type, key_bits = _inspect_public_key(cert.public_key())
    sig_alg = cert.signature_algorithm_oid.dotted_string
    sig_alg_name = getattr(cert.signature_hash_algorithm, "name", sig_alg)

    sans = _extract_sans(cert)
    subject = _format_name(cert.subject)
    issuer = _format_name(cert.issuer)
    is_self_signed = subject == issuer

    warnings = _build_warnings(
        days_left=days_left,
        key_type=key_type,
        key_bits=key_bits,
        sig_alg_oid=sig_alg,
        is_self_signed=is_self_signed,
    )

    return CertificateReport(
        subject=subject,
        issuer=issuer,
        serial_number=hex(cert.serial_number),
        not_before=cert.not_valid_before_utc,
        not_after=not_after,
        days_until_expiry=days_left,
        expiry_status=expiry_status,
        key_type=key_type,
        key_bits=key_bits,
        signature_algorithm=sig_alg_name,
        subject_alt_names=sans,
        is_self_signed=is_self_signed,
        warnings=warnings,
    )


def _classify_expiry(days_left: int) -> ExpiryStatus:
    if days_left < 0:
        return "expired"
    if days_left < CRITICAL_DAYS:
        return "critical"
    if days_left < WARNING_DAYS:
        return "warning"
    return "valid"


def _inspect_public_key(pub_key: object) -> tuple[str, int]:
    """Return (key_type_name, key_bits) for *pub_key*."""
    if isinstance(pub_key, rsa.RSAPublicKey):
        return "RSA", pub_key.key_size
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        return "EC", pub_key.key_size
    if isinstance(pub_key, DSAPublicKey):
        return "DSA", pub_key.key_size
    if isinstance(pub_key, Ed25519PublicKey):
        return "Ed25519", 255
    if isinstance(pub_key, Ed448PublicKey):
        return "Ed448", 448
    return "Unknown", 0


def _extract_sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return [str(name.value) for name in ext.value]
    except x509.ExtensionNotFound:
        return []


def _format_name(name: x509.Name) -> str:
    parts = []
    for oid, attr_name in [
        (NameOID.COMMON_NAME, "CN"),
        (NameOID.ORGANIZATION_NAME, "O"),
        (NameOID.COUNTRY_NAME, "C"),
    ]:
        try:
            value = name.get_attributes_for_oid(oid)[0].value
            parts.append(f"{attr_name}={value}")
        except IndexError:
            pass
    return ", ".join(parts) if parts else str(name)


def _build_warnings(
    *,
    days_left: int,
    key_type: str,
    key_bits: int,
    sig_alg_oid: str,
    is_self_signed: bool,
) -> list[str]:
    warnings: list[str] = []
    if days_left < 0:
        warnings.append(f"Certificate EXPIRED {abs(days_left)} days ago")
    elif days_left < CRITICAL_DAYS:
        warnings.append(f"Certificate expires in {days_left} days — CRITICAL")
    elif days_left < WARNING_DAYS:
        warnings.append(f"Certificate expires in {days_left} days — renew soon")
    if key_type == "RSA" and key_bits < MIN_RSA_BITS:
        warnings.append(f"Weak RSA key: {key_bits} bits (minimum: {MIN_RSA_BITS})")
    if key_type == "EC" and key_bits < MIN_EC_BITS:
        warnings.append(f"Weak EC key: {key_bits} bits (minimum: {MIN_EC_BITS})")
    if key_type == "DSA":
        warnings.append("DSA keys are deprecated — use RSA or EC")
    if sig_alg_oid in _WEAK_HASH_OIDS:
        warnings.append("Weak signature algorithm: SHA-1 is deprecated")
    if is_self_signed:
        warnings.append("Self-signed certificate — not trusted by browsers/OS")
    return warnings
