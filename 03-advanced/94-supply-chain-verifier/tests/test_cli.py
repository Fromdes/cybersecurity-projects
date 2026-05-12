"""Tests for project_94 CLI — Supply Chain Verifier."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from project_94.cli import cli


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def artifact(tmp_path: Path) -> Path:
    f = tmp_path / "app.tar.gz"
    f.write_bytes(b"release binary content")
    return f


@pytest.fixture()
def good_hash(artifact: Path) -> str:
    return hashlib.sha256(artifact.read_bytes()).hexdigest()


class TestHashCommand:
    def test_hash_output(self, runner: CliRunner, artifact: Path) -> None:
        result = runner.invoke(cli, ["hash", str(artifact)])
        assert result.exit_code == 0
        expected = hashlib.sha256(artifact.read_bytes()).hexdigest()
        assert expected in result.output

    def test_hash_sha512(self, runner: CliRunner, artifact: Path) -> None:
        result = runner.invoke(cli, ["hash", str(artifact), "--algorithm", "sha512"])
        assert result.exit_code == 0
        expected = hashlib.sha512(artifact.read_bytes()).hexdigest()
        assert expected in result.output


class TestVerifyCommand:
    def test_verify_correct_hash_passes(self, runner: CliRunner, artifact: Path, good_hash: str) -> None:
        result = runner.invoke(cli, ["verify", str(artifact), "--expected-hash", good_hash])
        assert result.exit_code == 0
        assert "PASS" in result.output

    def test_verify_wrong_hash_fails(self, runner: CliRunner, artifact: Path) -> None:
        result = runner.invoke(cli, ["verify", str(artifact), "--expected-hash", "badhash"])
        assert result.exit_code == 0
        assert "FAIL" in result.output

    def test_exit_code_on_fail(self, runner: CliRunner, artifact: Path) -> None:
        result = runner.invoke(cli, ["verify", str(artifact), "--expected-hash", "badhash", "--exit-code"])
        assert result.exit_code == 1

    def test_verify_no_hash_passes_existence(self, runner: CliRunner, artifact: Path) -> None:
        result = runner.invoke(cli, ["verify", str(artifact)])
        assert result.exit_code == 0
        assert "PASS" in result.output

    def test_verify_with_attestation(self, runner: CliRunner, artifact: Path, tmp_path: Path) -> None:
        sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
        attestation = {
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": artifact.name, "digest": {"sha256": sha}}],
            "predicate": {
                "builder": {"id": "https://github.com/actions"},
                "buildType": "x",
                "invocation": {"cfg": "x"},
                "materials": [{"uri": "git+https://github.com/repo"}],
            },
        }
        att_file = tmp_path / "att.json"
        att_file.write_text(json.dumps(attestation))
        result = runner.invoke(cli, ["verify", str(artifact), "--attestation", str(att_file)])
        assert result.exit_code == 0
        assert "slsa_level" in result.output or "Provenance" in result.output

    def test_verify_output_json(self, runner: CliRunner, artifact: Path, tmp_path: Path, good_hash: str) -> None:
        out = tmp_path / "report.json"
        result = runner.invoke(cli, ["verify", str(artifact), "--expected-hash", good_hash, "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "checks" in data


class TestCheckSumsCommand:
    def test_verify_all_matching(self, runner: CliRunner, tmp_path: Path) -> None:
        f1 = tmp_path / "file1.bin"
        f1.write_bytes(b"content1")
        sha1 = hashlib.sha256(b"content1").hexdigest()
        sums = tmp_path / "sha256sums"
        sums.write_text(f"{sha1}  file1.bin\n")
        result = runner.invoke(cli, ["check-sums", str(sums)])
        assert result.exit_code == 0
        assert "OK" in result.output

    def test_exit_code_on_mismatch(self, runner: CliRunner, tmp_path: Path) -> None:
        f1 = tmp_path / "file1.bin"
        f1.write_bytes(b"content1")
        sums = tmp_path / "sha256sums"
        sums.write_text("wronghash  file1.bin\n")
        result = runner.invoke(cli, ["check-sums", str(sums), "--exit-code"])
        assert result.exit_code == 1


class TestVersionOption:
    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
