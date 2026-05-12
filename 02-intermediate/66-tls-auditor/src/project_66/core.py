"""TLS configuration auditor — checks cipher suites, protocol versions, and cert validity."""

from __future__ import annotations

import datetime
import socket
import ssl
from dataclasses import dataclass, field
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WEAK_PROTOCOLS: Final[frozenset[str]] = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})

WEAK_CIPHERS: Final[frozenset[str]] = frozenset({
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon", "ADH", "AECDH",
})

STRONG_PROTOCOLS: Final[frozenset[str]] = frozenset({"TLSv1.2", "TLSv1.3"})

CERT_WARN_DAYS: Final[int] = 30
CERT_CRITICAL_DAYS: Final[int] = 7

DEFAULT_TIMEOUT: Final[int] = 10


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CipherInfo:
    """Information about a negotiated cipher suite."""

    name: str
    protocol: str
    bits: int

    @property
    def is_weak(self) -> bool:
        """Return True if the cipher is considered weak."""
        return any(weak in self.name for weak in WEAK_CIPHERS)


@dataclass(frozen=True)
class CertInfo:
    """Parsed X.509 certificate metadata."""

    subject: dict[str, str]
    issuer: dict[str, str]
    not_before: datetime.datetime
    not_after: datetime.datetime
    san: list[str]
    serial_number: str
    signature_algorithm: str

    @property
    def days_until_expiry(self) -> int:
        """Return days until certificate expires (negative if already expired)."""
        now = datetime.datetime.now(tz=datetime.UTC)
        expiry = self.not_after
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=datetime.UTC)
        delta = expiry - now
        return delta.days

    @property
    def is_expired(self) -> bool:
        """Return True if the certificate has expired."""
        return self.days_until_expiry < 0

    @property
    def expiry_severity(self) -> str:
        """Return 'critical', 'warning', or 'ok' based on expiry proximity."""
        days = self.days_until_expiry
        if days < 0:
            return "expired"
        if days <= CERT_CRITICAL_DAYS:
            return "critical"
        if days <= CERT_WARN_DAYS:
            return "warning"
        return "ok"


@dataclass
class TLSAuditResult:
    """Complete TLS audit result for a host."""

    host: str
    port: int
    connected: bool = False
    protocol_version: str = ""
    cipher: CipherInfo | None = None
    cert: CertInfo | None = None
    findings: list[str] = field(default_factory=list)
    score: int = 100  # starts at 100, deductions applied

    def add_finding(self, severity: str, message: str, deduction: int = 0) -> None:
        """Record a finding and apply score deduction."""
        self.findings.append(f"[{severity.upper()}] {message}")
        self.score = max(0, self.score - deduction)

    @property
    def grade(self) -> str:
        """Letter grade based on score."""
        if self.score >= 90:
            return "A"
        if self.score >= 80:
            return "B"
        if self.score >= 70:
            return "C"
        if self.score >= 60:
            return "D"
        return "F"


# ---------------------------------------------------------------------------
# Certificate parsing helpers
# ---------------------------------------------------------------------------

def _parse_dn(dn_tuples: tuple[tuple[str, str], ...]) -> dict[str, str]:
    """Convert SSL certificate DN tuple list to dict."""
    return {k: v for k, v in dn_tuples}


def _parse_cert(cert: dict) -> CertInfo:  # type: ignore[type-arg]
    """Parse ssl.getpeercert() dict into CertInfo."""
    subject = _parse_dn(tuple(pair for rdn in cert.get("subject", ()) for pair in rdn))
    issuer = _parse_dn(tuple(pair for rdn in cert.get("issuer", ()) for pair in rdn))

    not_before = ssl.cert_time_to_seconds(cert["notBefore"])
    not_after = ssl.cert_time_to_seconds(cert["notAfter"])

    san: list[str] = []
    for san_type, san_value in cert.get("subjectAltName", ()):
        san.append(f"{san_type}:{san_value}")

    return CertInfo(
        subject=subject,
        issuer=issuer,
        not_before=datetime.datetime.fromtimestamp(not_before, tz=datetime.UTC),
        not_after=datetime.datetime.fromtimestamp(not_after, tz=datetime.UTC),
        san=san,
        serial_number=str(cert.get("serialNumber", "")),
        signature_algorithm=cert.get("signatureAlgorithm", "unknown"),
    )


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------

def audit_tls(host: str, port: int = 443, *, timeout: int = DEFAULT_TIMEOUT) -> TLSAuditResult:
    """Connect to host:port and audit TLS configuration.

    Args:
        host: Hostname or IP address to audit.
        port: TCP port (default 443).
        timeout: Connection timeout in seconds.

    Returns:
        TLSAuditResult with findings and score.
    """
    result = TLSAuditResult(host=host, port=port)

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                result.connected = True
                result.protocol_version = tls_sock.version() or ""

                cipher_tuple = tls_sock.cipher()
                if cipher_tuple:
                    result.cipher = CipherInfo(
                        name=cipher_tuple[0],
                        protocol=cipher_tuple[1],
                        bits=cipher_tuple[2] or 0,
                    )

                peer_cert = tls_sock.getpeercert()
                if peer_cert:
                    result.cert = _parse_cert(peer_cert)

    except ssl.SSLCertVerificationError as exc:
        result.add_finding("critical", f"Certificate verification failed: {exc}", deduction=40)
        return result
    except TimeoutError:
        result.add_finding("info", f"Connection timed out after {timeout}s")
        return result
    except (OSError, ssl.SSLError) as exc:
        result.add_finding("info", f"Connection failed: {exc}")
        return result

    _analyse_protocol(result)
    _analyse_cipher(result)
    _analyse_cert(result)

    return result


def _analyse_protocol(result: TLSAuditResult) -> None:
    """Check protocol version and apply findings."""
    proto = result.protocol_version
    if proto in WEAK_PROTOCOLS:
        result.add_finding("critical", f"Weak protocol in use: {proto}", deduction=30)
    elif proto not in STRONG_PROTOCOLS and proto:
        result.add_finding("warning", f"Unrecognised protocol version: {proto}", deduction=10)


def _analyse_cipher(result: TLSAuditResult) -> None:
    """Check cipher suite and apply findings."""
    if result.cipher is None:
        return
    cipher = result.cipher
    if cipher.is_weak:
        result.add_finding("critical", f"Weak cipher suite: {cipher.name}", deduction=25)
    if cipher.bits < 128:
        result.add_finding("critical", f"Insufficient key length: {cipher.bits} bits", deduction=20)
    elif cipher.bits < 256:
        result.add_finding("info", f"Key length {cipher.bits} bits (256 preferred)")


def _analyse_cert(result: TLSAuditResult) -> None:
    """Check certificate validity and apply findings."""
    cert = result.cert
    if cert is None:
        result.add_finding("critical", "No certificate returned", deduction=40)
        return

    if cert.is_expired:
        result.add_finding("critical", "Certificate is EXPIRED", deduction=40)
    elif cert.expiry_severity == "critical":
        result.add_finding("critical", f"Certificate expires in {cert.days_until_expiry} days", deduction=20)
    elif cert.expiry_severity == "warning":
        result.add_finding("warning", f"Certificate expires in {cert.days_until_expiry} days", deduction=5)

    if "sha1" in cert.signature_algorithm.lower():
        result.add_finding("critical", f"Weak signature algorithm: {cert.signature_algorithm}", deduction=20)
    elif "md5" in cert.signature_algorithm.lower():
        result.add_finding("critical", f"Broken signature algorithm: {cert.signature_algorithm}", deduction=30)

    if not cert.san:
        result.add_finding("warning", "No Subject Alternative Names (SANs) present", deduction=5)


def analyse_result(result: TLSAuditResult) -> dict[str, object]:
    """Return a structured summary dict suitable for JSON output.

    Args:
        result: A completed TLSAuditResult.

    Returns:
        Dict with host, grade, score, findings, and certificate metadata.
    """
    summary: dict[str, object] = {
        "host": result.host,
        "port": result.port,
        "connected": result.connected,
        "protocol": result.protocol_version,
        "grade": result.grade,
        "score": result.score,
        "findings": result.findings,
    }
    if result.cipher:
        summary["cipher"] = {
            "name": result.cipher.name,
            "bits": result.cipher.bits,
            "weak": result.cipher.is_weak,
        }
    if result.cert:
        summary["certificate"] = {
            "subject": result.cert.subject,
            "issuer": result.cert.issuer,
            "expires": result.cert.not_after.isoformat(),
            "days_remaining": result.cert.days_until_expiry,
            "expiry_status": result.cert.expiry_severity,
            "san_count": len(result.cert.san),
            "signature_algorithm": result.cert.signature_algorithm,
        }
    return summary
