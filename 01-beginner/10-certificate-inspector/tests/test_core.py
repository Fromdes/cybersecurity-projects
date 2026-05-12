"""Unit tests for project_10.core — uses a self-signed test certificate."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from project_10.core import (
    inspect_certificate,
    load_from_file,
)


def _make_self_signed_cert(
    key_size: int = 2048,
    days_valid: int = 365,
    key_type: str = "rsa",
) -> tuple[x509.Certificate, bytes]:
    """Generate a self-signed certificate for testing."""
    if key_type == "ec":
        private_key: object = ec.generate_private_key(ec.SECP256R1())
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size
        )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
    ])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())  # type: ignore[attr-defined]
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("test.example.com")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())  # type: ignore[arg-type]
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert, pem


@pytest.fixture(scope="module")
def valid_cert() -> x509.Certificate:
    cert, _ = _make_self_signed_cert(days_valid=365)
    return cert


@pytest.fixture(scope="module")
def expiring_cert() -> x509.Certificate:
    cert, _ = _make_self_signed_cert(days_valid=5)
    return cert


@pytest.fixture(scope="module")
def pem_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    _, pem = _make_self_signed_cert()
    p = tmp_path_factory.mktemp("certs") / "test.pem"
    p.write_bytes(pem)
    return p


class TestLoadFromFile:
    def test_loads_pem(self, pem_file: Path) -> None:
        cert = load_from_file(pem_file)
        assert cert is not None

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_from_file(tmp_path / "no.pem")

    def test_invalid_file_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.pem"
        bad.write_bytes(b"not a certificate")
        with pytest.raises(ValueError):
            load_from_file(bad)


class TestInspectCertificate:
    def test_subject_extracted(self, valid_cert: x509.Certificate) -> None:
        report = inspect_certificate(valid_cert)
        assert "test.example.com" in report.subject

    def test_self_signed_detected(self, valid_cert: x509.Certificate) -> None:
        report = inspect_certificate(valid_cert)
        assert report.is_self_signed

    def test_valid_expiry_status(self, valid_cert: x509.Certificate) -> None:
        report = inspect_certificate(valid_cert)
        assert report.expiry_status == "valid"

    def test_expiring_cert_status(self, expiring_cert: x509.Certificate) -> None:
        report = inspect_certificate(expiring_cert)
        assert report.expiry_status in ("warning", "critical")

    def test_rsa_key_type(self, valid_cert: x509.Certificate) -> None:
        report = inspect_certificate(valid_cert)
        assert report.key_type == "RSA"
        assert report.key_bits == 2048

    def test_ec_key_type(self) -> None:
        cert, _ = _make_self_signed_cert(key_type="ec")
        report = inspect_certificate(cert)
        assert report.key_type == "EC"

    def test_san_extracted(self, valid_cert: x509.Certificate) -> None:
        report = inspect_certificate(valid_cert)
        assert "test.example.com" in report.subject_alt_names

    def test_self_signed_warning(self, valid_cert: x509.Certificate) -> None:
        report = inspect_certificate(valid_cert)
        assert any("self-signed" in w.lower() for w in report.warnings)

    def test_weak_rsa_key_warning(self) -> None:
        cert, _ = _make_self_signed_cert(key_size=1024)
        report = inspect_certificate(cert)
        assert any("Weak RSA" in w for w in report.warnings)

    def test_report_is_frozen(self, valid_cert: x509.Certificate) -> None:
        report = inspect_certificate(valid_cert)
        with pytest.raises((TypeError, AttributeError)):
            report.subject = "tampered"  # type: ignore[misc]

    def test_days_until_expiry_positive_for_valid(self, valid_cert: x509.Certificate) -> None:
        report = inspect_certificate(valid_cert)
        assert report.days_until_expiry > 0

    def test_serial_number_is_hex(self, valid_cert: x509.Certificate) -> None:
        report = inspect_certificate(valid_cert)
        assert report.serial_number.startswith("0x")
