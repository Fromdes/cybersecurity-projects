"""Tests for project_94 core — Supply Chain Verifier."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from project_94.core import (
    hash_artifact,
    parse_checksums_file,
    parse_slsa_attestation,
    verify_artifact,
    verify_hash,
)

# ── hash_artifact / verify_hash ───────────────────────────────────────────────

class TestHashArtifact:
    def test_sha256(self, tmp_path: Path) -> None:
        f = tmp_path / "file.bin"
        f.write_bytes(b"hello world")
        digest = hash_artifact(f)
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert digest == expected

    def test_sha512(self, tmp_path: Path) -> None:
        f = tmp_path / "file.bin"
        f.write_bytes(b"test")
        digest = hash_artifact(f, "sha512")
        expected = hashlib.sha512(b"test").hexdigest()
        assert digest == expected

    def test_unsupported_algorithm(self, tmp_path: Path) -> None:
        f = tmp_path / "file.bin"
        f.write_bytes(b"x")
        with pytest.raises(ValueError, match="Unsupported"):
            hash_artifact(f, "crc32")


class TestVerifyHash:
    def test_correct_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_bytes(b"content")
        expected = hashlib.sha256(b"content").hexdigest()
        assert verify_hash(f, expected) is True

    def test_wrong_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_bytes(b"content")
        assert verify_hash(f, "deadbeef" * 8) is False

    def test_case_insensitive(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_bytes(b"data")
        expected = hashlib.sha256(b"data").hexdigest().upper()
        assert verify_hash(f, expected) is True


# ── parse_checksums_file ──────────────────────────────────────────────────────

class TestParseChecksumsFile:
    def test_parses_sha256sums(self, tmp_path: Path) -> None:
        content = "abc123  file1.tar.gz\ndef456  file2.tar.gz\n"
        f = tmp_path / "sha256sums"
        f.write_text(content)
        entries = parse_checksums_file(f)
        assert len(entries) == 2
        assert entries[0].filename == "file1.tar.gz"
        assert entries[0].digest == "abc123"

    def test_ignores_comments(self, tmp_path: Path) -> None:
        content = "# This is a comment\nabc123  file.tar.gz\n"
        f = tmp_path / "sha256sums"
        f.write_text(content)
        entries = parse_checksums_file(f)
        assert len(entries) == 1

    def test_infers_sha512_from_filename(self, tmp_path: Path) -> None:
        f = tmp_path / "sha512sums"
        f.write_text("abc  file.bin\n")
        entries = parse_checksums_file(f)
        assert entries[0].algorithm == "sha512"

    def test_star_prefix_stripped(self, tmp_path: Path) -> None:
        f = tmp_path / "sha256sums"
        f.write_text("abc123 *file.bin\n")
        entries = parse_checksums_file(f)
        assert entries[0].filename == "file.bin"


# ── parse_slsa_attestation ────────────────────────────────────────────────────

class TestParseSLSAAttestation:
    def _attestation(self, builder_id: str = "https://github.com/slsa-framework/slsa-github-generator",
                     predicate_type: str = "https://slsa.dev/provenance/v1") -> dict:
        return {
            "predicateType": predicate_type,
            "subject": [{"name": "myapp.tar.gz", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "builder": {"id": builder_id},
                "buildType": "https://github.com/slsa-framework/slsa-github-generator/linux-buildless@v0",
                "invocation": {"configSource": {"uri": "git+https://github.com/example/repo"}},
                "materials": [{"uri": "git+https://github.com/example/repo", "digest": {"sha1": "deadbeef"}}],
            },
        }

    def test_parses_subjects(self) -> None:
        prov = parse_slsa_attestation(self._attestation())
        assert len(prov.subjects) == 1
        assert prov.subjects[0].name == "myapp.tar.gz"

    def test_infers_slsa_level_3_hosted_builder(self) -> None:
        prov = parse_slsa_attestation(self._attestation())
        assert prov.slsa_level == 3

    def test_infers_slsa_level_1_unknown_builder(self) -> None:
        att = self._attestation(builder_id="local-builder")
        prov = parse_slsa_attestation(att)
        assert prov.slsa_level <= 2

    def test_builder_id_stored(self) -> None:
        prov = parse_slsa_attestation(self._attestation())
        assert "github.com" in prov.builder_id

    def test_to_dict_keys(self) -> None:
        prov = parse_slsa_attestation(self._attestation())
        d = prov.to_dict()
        assert set(d.keys()) >= {"builder_id", "slsa_level", "subjects"}


# ── verify_artifact ───────────────────────────────────────────────────────────

class TestVerifyArtifact:
    def test_hash_match_passes(self, tmp_path: Path) -> None:
        f = tmp_path / "app.bin"
        f.write_bytes(b"release content")
        expected = hashlib.sha256(b"release content").hexdigest()
        result = verify_artifact(f, expected_hash=expected)
        assert result.passed is True

    def test_hash_mismatch_fails(self, tmp_path: Path) -> None:
        f = tmp_path / "app.bin"
        f.write_bytes(b"release content")
        result = verify_artifact(f, expected_hash="wronghash" * 4)
        assert result.passed is False

    def test_missing_artifact_fails(self, tmp_path: Path) -> None:
        result = verify_artifact(tmp_path / "nonexistent.bin")
        assert result.passed is False

    def test_with_valid_attestation(self, tmp_path: Path) -> None:
        content = b"my artifact"
        artifact = tmp_path / "app.bin"
        artifact.write_bytes(content)
        sha = hashlib.sha256(content).hexdigest()
        attestation_data = {
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": "app.bin", "digest": {"sha256": sha}}],
            "predicate": {
                "builder": {"id": "https://github.com/actions/runner"},
                "buildType": "https://github.com/slsa-framework",
                "invocation": {"config": "workflow.yml"},
                "materials": [{"uri": "git+https://github.com/example/repo"}],
            },
        }
        att_file = tmp_path / "app.bin.attestation.json"
        att_file.write_text(json.dumps(attestation_data))
        result = verify_artifact(artifact, attestation_path=att_file, min_slsa_level=1)
        check_names = {c.name for c in result.checks}
        assert "provenance_subject_match" in check_names
        assert "slsa_level" in check_names

    def test_attestation_subject_mismatch_fails(self, tmp_path: Path) -> None:
        artifact = tmp_path / "app.bin"
        artifact.write_bytes(b"real content")
        attestation_data = {
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": "app.bin", "digest": {"sha256": "wronghash" * 4}}],
            "predicate": {
                "builder": {"id": "https://github.com/actions"},
                "buildType": "x",
                "invocation": {},
                "materials": [],
            },
        }
        att_file = tmp_path / "att.json"
        att_file.write_text(json.dumps(attestation_data))
        result = verify_artifact(artifact, attestation_path=att_file)
        subject_check = next(c for c in result.checks if c.name == "provenance_subject_match")
        assert subject_check.passed is False

    def test_trusted_builder_check(self, tmp_path: Path) -> None:
        content = b"data"
        artifact = tmp_path / "app.bin"
        artifact.write_bytes(content)
        sha = hashlib.sha256(content).hexdigest()
        attestation_data = {
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": "app.bin", "digest": {"sha256": sha}}],
            "predicate": {
                "builder": {"id": "https://github.com/trusted-builder"},
                "buildType": "x",
                "invocation": {"cfg": "x"},
                "materials": [{"uri": "git+https://github.com/repo"}],
            },
        }
        att_file = tmp_path / "att.json"
        att_file.write_text(json.dumps(attestation_data))
        result = verify_artifact(
            artifact, attestation_path=att_file,
            trusted_builders=["github.com/trusted-builder"],
        )
        trusted_check = next((c for c in result.checks if c.name == "trusted_builder"), None)
        assert trusted_check is not None
        assert trusted_check.passed is True

    def test_to_dict_structure(self, tmp_path: Path) -> None:
        f = tmp_path / "file.bin"
        f.write_bytes(b"x")
        result = verify_artifact(f)
        d = result.to_dict()
        assert "artifact_name" in d
        assert "passed" in d
        assert "checks" in d
