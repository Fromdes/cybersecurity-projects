"""CLI tests for project_10."""

from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from project_10.cli import main


def _make_pem(tmp_path: Path, days: int = 365) -> Path:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "cli-test.example.com"),
    ])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(private_key, hashes.SHA256())
    )
    pem_path = tmp_path / "test.pem"
    pem_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return pem_path


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    sys.argv = ["cert-inspect"] + args
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return int(exc.value.code or 0), captured.out, captured.err


class TestFileCLI:
    def test_inspect_valid_cert(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pem = _make_pem(tmp_path)
        code, out, _ = _run(["file", str(pem)], capsys)
        assert "Subject" in out

    def test_json_output(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pem = _make_pem(tmp_path)
        code, out, _ = _run(["file", str(pem), "--json"], capsys)
        data = json.loads(out)
        assert "subject" in data
        assert "expiry_status" in data
        assert "warnings" in data

    def test_missing_file_exits_1(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, _, err = _run(["file", "/no/such/cert.pem"], capsys)
        assert code == 1

    def test_self_signed_cert_has_warnings(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pem = _make_pem(tmp_path)
        code, out, _ = _run(["file", str(pem)], capsys)
        assert "Warnings" in out or code == 1
