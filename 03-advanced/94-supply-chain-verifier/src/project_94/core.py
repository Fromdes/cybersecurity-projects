"""Supply Chain Verifier — verify artifact integrity and SLSA provenance attestations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ── Hash verification ─────────────────────────────────────────────────────────

SUPPORTED_ALGORITHMS: frozenset[str] = frozenset({"sha256", "sha512", "sha384", "sha1", "md5"})


def hash_artifact(path: Path, algorithm: str = "sha256") -> str:
    """Compute a hex digest of *path* using *algorithm*."""
    alg = algorithm.lower()
    if alg not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    h = hashlib.new(alg)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_hash(path: Path, expected: str, algorithm: str = "sha256") -> bool:
    """Return True if the artifact matches the expected hash."""
    actual = hash_artifact(path, algorithm)
    return actual.lower() == expected.lower()


# ── Checksum file (sha256sums / sha512sums format) ────────────────────────────

@dataclass(frozen=True)
class ChecksumEntry:
    """One entry from a checksums file."""

    filename: str
    digest: str
    algorithm: str


def parse_checksums_file(path: Path) -> list[ChecksumEntry]:
    """Parse a `sha256sums`-style checksums file into entries."""
    entries: list[ChecksumEntry] = []
    algorithm = "sha256"
    # Infer algorithm from file name
    stem = path.stem.lower()
    for alg in SUPPORTED_ALGORITHMS:
        if alg in stem:
            algorithm = alg
            break
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Format: "<hash>  <filename>" or "<hash> *<filename>"
        parts = re.split(r"\s+\*?", line, maxsplit=1)
        if len(parts) == 2:
            digest, filename = parts
            entries.append(ChecksumEntry(filename=filename, digest=digest, algorithm=algorithm))
    return entries


# ── SLSA provenance attestation ───────────────────────────────────────────────

@dataclass(frozen=True)
class SLSASubject:
    """A subject artifact referenced in a SLSA provenance attestation."""

    name: str
    digest: dict[str, str]


@dataclass(frozen=True)
class SLSAProvenance:
    """Parsed SLSA in-toto provenance attestation."""

    predicate_type: str
    builder_id: str
    build_type: str
    subjects: list[SLSASubject]
    invocation: dict[str, Any]
    materials: list[dict[str, Any]]
    slsa_level: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "predicate_type": self.predicate_type,
            "builder_id": self.builder_id,
            "build_type": self.build_type,
            "slsa_level": self.slsa_level,
            "subjects": [{"name": s.name, "digest": s.digest} for s in self.subjects],
            "invocation": self.invocation,
            "materials": self.materials,
        }


def parse_slsa_attestation(data: dict[str, Any]) -> SLSAProvenance:
    """Parse an in-toto SLSA provenance attestation dict."""
    predicate_type = data.get("predicateType", "")
    predicate = data.get("predicate", {})
    builder = predicate.get("builder", {})
    invocation = predicate.get("invocation", {})
    materials = predicate.get("materials", [])

    raw_subjects = data.get("subject", [])
    subjects: list[SLSASubject] = []
    for s in raw_subjects:
        subjects.append(SLSASubject(
            name=s.get("name", ""),
            digest=s.get("digest", {}),
        ))

    slsa_level = _infer_slsa_level(builder.get("id", ""), predicate_type, invocation, materials)

    return SLSAProvenance(
        predicate_type=predicate_type,
        builder_id=builder.get("id", "unknown"),
        build_type=predicate.get("buildType", ""),
        subjects=subjects,
        invocation=invocation,
        materials=materials,
        slsa_level=slsa_level,
    )


def _infer_slsa_level(builder_id: str, predicate_type: str, invocation: dict, materials: list) -> int:
    """Infer SLSA level from attestation fields."""
    # Level 3+: hosted build platform (GitHub Actions, etc.)
    hosted_builders = (
        "github.com/", "gitlab.com/", "google.com/", "cloudbuild",
    )
    is_hosted = any(b in builder_id.lower() for b in hosted_builders)
    has_materials = bool(materials)
    has_invocation = bool(invocation)
    is_slsa_v1 = "slsa.dev/provenance/v1" in predicate_type

    if is_hosted and has_materials and has_invocation:
        return 3 if is_slsa_v1 else 2
    if has_invocation:
        return 2
    if builder_id and builder_id != "unknown":
        return 1
    return 0


# ── Verification result ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class VerificationCheck:
    """One check within a verification result."""

    name: str
    passed: bool
    detail: str


@dataclass
class VerificationResult:
    """Full artifact verification result."""

    artifact_name: str
    checks: list[VerificationCheck]
    provenance: SLSAProvenance | None = None

    @property
    def passed(self) -> bool:
        """Return True only if all checks passed."""
        return all(c.passed for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "artifact_name": self.artifact_name,
            "passed": self.passed,
            "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in self.checks],
            "provenance": self.provenance.to_dict() if self.provenance else None,
        }


def verify_artifact(
    artifact_path: Path,
    *,
    expected_hash: str | None = None,
    hash_algorithm: str = "sha256",
    attestation_path: Path | None = None,
    min_slsa_level: int = 0,
    trusted_builders: list[str] | None = None,
) -> VerificationResult:
    """Verify an artifact against expected hash and optional SLSA provenance."""
    checks: list[VerificationCheck] = []
    provenance: SLSAProvenance | None = None

    # Existence check
    checks.append(VerificationCheck(
        name="artifact_exists",
        passed=artifact_path.exists(),
        detail=str(artifact_path),
    ))

    if not artifact_path.exists():
        return VerificationResult(artifact_name=artifact_path.name, checks=checks)

    # Hash verification
    if expected_hash:
        match = verify_hash(artifact_path, expected_hash, hash_algorithm)
        actual = hash_artifact(artifact_path, hash_algorithm)
        checks.append(VerificationCheck(
            name=f"hash_{hash_algorithm}",
            passed=match,
            detail=f"expected={expected_hash[:16]}… actual={actual[:16]}…" if not match else "OK",
        ))

    # SLSA provenance verification
    if attestation_path:
        if not attestation_path.exists():
            checks.append(VerificationCheck(
                name="attestation_exists",
                passed=False,
                detail=f"Attestation not found: {attestation_path}",
            ))
        else:
            try:
                data = json.loads(attestation_path.read_text())
                provenance = parse_slsa_attestation(data)

                # Check subject hash matches artifact
                actual_hash = hash_artifact(artifact_path, "sha256")
                subject_match = any(
                    s.digest.get("sha256", "").lower() == actual_hash.lower()
                    for s in provenance.subjects
                )
                checks.append(VerificationCheck(
                    name="provenance_subject_match",
                    passed=subject_match,
                    detail="Artifact sha256 found in provenance subjects" if subject_match
                           else f"Artifact sha256 {actual_hash[:16]}… not in subjects",
                ))

                # SLSA level check
                level_ok = provenance.slsa_level >= min_slsa_level
                checks.append(VerificationCheck(
                    name="slsa_level",
                    passed=level_ok,
                    detail=f"Level {provenance.slsa_level} (required: {min_slsa_level})",
                ))

                # Trusted builder check
                if trusted_builders:
                    builder_ok = any(
                        tb in provenance.builder_id for tb in trusted_builders
                    )
                    checks.append(VerificationCheck(
                        name="trusted_builder",
                        passed=builder_ok,
                        detail=f"Builder: {provenance.builder_id}",
                    ))

            except (json.JSONDecodeError, KeyError) as exc:
                checks.append(VerificationCheck(
                    name="attestation_parse",
                    passed=False,
                    detail=f"Parse error: {exc}",
                ))

    return VerificationResult(
        artifact_name=artifact_path.name,
        checks=checks,
        provenance=provenance,
    )
