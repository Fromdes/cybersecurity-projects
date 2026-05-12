"""JWT Validator & Inspector — core validation and inspection logic.

Defends against: T1552.001 (Credentials in Files), T1078 (Valid Accounts),
T1606 (Forge Web Credentials), T1550.001 (Use Alternate Auth Material: App Access Token).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import jwt  # PyJWT
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import load_pem_x509_certificate

logger = logging.getLogger(__name__)

LEEWAY_SECONDS: int = 0
MAX_TOKEN_AGE_SECONDS: int = 86400  # 24 h hard cap
DANGEROUS_ALGORITHMS: frozenset[str] = frozenset({"none", "HS256", "HS384", "HS512"})
WEAK_ALGORITHMS: frozenset[str] = frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"})


class ValidationStatus(StrEnum):
    """Outcome of a JWT validation run."""

    VALID = "VALID"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    MALFORMED = "MALFORMED"
    DANGEROUS_ALGORITHM = "DANGEROUS_ALGORITHM"
    MISSING_CLAIM = "MISSING_CLAIM"
    AUDIENCE_MISMATCH = "AUDIENCE_MISMATCH"
    ISSUER_MISMATCH = "ISSUER_MISMATCH"
    TOKEN_TOO_OLD = "TOKEN_TOO_OLD"


@dataclass(frozen=True)
class JWTHeader:
    """Decoded JWT JOSE header."""

    algorithm: str
    token_type: str | None
    key_id: str | None
    raw: dict[str, Any]


@dataclass(frozen=True)
class JWTClaims:
    """Standard JWT claims extracted from payload."""

    subject: str | None
    issuer: str | None
    audience: list[str] | None
    issued_at: int | None
    expiry: int | None
    not_before: int | None
    jwt_id: str | None
    raw: dict[str, Any]


@dataclass
class ValidationResult:
    """Full result of JWT validation."""

    status: ValidationStatus
    header: JWTHeader | None = None
    claims: JWTClaims | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    fingerprint: str | None = None

    @property
    def is_valid(self) -> bool:
        """Return True only when status is VALID."""
        return self.status == ValidationStatus.VALID


def _b64_decode_unpadded(data: str) -> bytes:
    """Decode base64url without padding."""
    padding = 4 - len(data) % 4
    data += "=" * (padding % 4)
    return base64.urlsafe_b64decode(data)


def decode_header_unsafe(token: str) -> dict[str, Any]:
    """Decode JWT header without any verification (for inspection only)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("JWT must have exactly three parts")
        raw: dict[str, Any] = json.loads(_b64_decode_unpadded(parts[0]))
        return raw
    except Exception as exc:
        raise ValueError(f"Cannot decode JWT header: {exc}") from exc


def decode_payload_unsafe(token: str) -> dict[str, Any]:
    """Decode JWT payload without signature verification (inspection only)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("JWT must have exactly three parts")
        raw: dict[str, Any] = json.loads(_b64_decode_unpadded(parts[1]))
        return raw
    except Exception as exc:
        raise ValueError(f"Cannot decode JWT payload: {exc}") from exc


def _parse_header(raw: dict[str, Any]) -> JWTHeader:
    return JWTHeader(
        algorithm=str(raw.get("alg", "unknown")),
        token_type=raw.get("typ"),
        key_id=raw.get("kid"),
        raw=raw,
    )


def _parse_claims(raw: dict[str, Any]) -> JWTClaims:
    aud = raw.get("aud")
    if isinstance(aud, str):
        aud = [aud]
    return JWTClaims(
        subject=raw.get("sub"),
        issuer=raw.get("iss"),
        audience=aud,
        issued_at=raw.get("iat"),
        expiry=raw.get("exp"),
        not_before=raw.get("nbf"),
        jwt_id=raw.get("jti"),
        raw=raw,
    )


def _token_fingerprint(token: str) -> str:
    """SHA-256 fingerprint of the raw token bytes."""
    return hashlib.sha256(token.encode()).hexdigest()


def inspect_token(token: str) -> ValidationResult:
    """Parse and inspect a JWT without signature verification.

    Args:
        token: Raw JWT string.

    Returns:
        ValidationResult with decoded header/claims and warnings.
    """
    result = ValidationResult(status=ValidationStatus.VALID)
    result.fingerprint = _token_fingerprint(token)

    try:
        raw_header = decode_header_unsafe(token)
        raw_payload = decode_payload_unsafe(token)
    except ValueError as exc:
        result.status = ValidationStatus.MALFORMED
        result.errors.append(str(exc))
        return result

    header = _parse_header(raw_header)
    claims = _parse_claims(raw_payload)
    result.header = header
    result.claims = claims

    alg = header.algorithm.lower()
    if alg == "none":
        result.warnings.append("Algorithm 'none' disables signature verification — CRITICAL risk")
        result.status = ValidationStatus.DANGEROUS_ALGORITHM
    elif header.algorithm in DANGEROUS_ALGORITHMS:
        result.warnings.append(
            f"Symmetric algorithm {header.algorithm} shares key between issuer and verifier"
        )

    now = int(time.time())
    if claims.expiry is not None and claims.expiry < now:
        result.warnings.append(f"Token expired {now - claims.expiry}s ago")
    if claims.issued_at is not None and (now - claims.issued_at) > MAX_TOKEN_AGE_SECONDS:
        result.warnings.append("Token age exceeds 24-hour hard cap")
    if claims.not_before is not None and claims.not_before > now:
        result.warnings.append("Token not yet valid (nbf claim)")

    for claim in ("iss", "sub", "exp", "iat"):
        if raw_payload.get(claim) is None:
            result.warnings.append(f"Recommended claim '{claim}' is absent")

    return result


def validate_token(
    token: str,
    secret_or_pubkey: str,
    *,
    algorithms: list[str] | None = None,
    expected_issuer: str | None = None,
    expected_audience: str | None = None,
    required_claims: list[str] | None = None,
) -> ValidationResult:
    """Validate a JWT signature and standard claims.

    Args:
        token: Raw JWT string.
        secret_or_pubkey: HMAC secret or PEM public key string.
        algorithms: Allowed algorithm list (defaults to RS256/ES256/PS256 family).
        expected_issuer: If set, 'iss' claim must match.
        expected_audience: If set, 'aud' claim must contain this value.
        required_claims: Extra claims that must be present.

    Returns:
        ValidationResult describing outcome.
    """
    result = ValidationResult(status=ValidationStatus.VALID)
    result.fingerprint = _token_fingerprint(token)

    allowed_algs = algorithms or list(WEAK_ALGORITHMS)

    try:
        raw_header = decode_header_unsafe(token)
    except ValueError as exc:
        result.status = ValidationStatus.MALFORMED
        result.errors.append(str(exc))
        return result

    header = _parse_header(raw_header)
    result.header = header

    if header.algorithm.lower() == "none":
        result.status = ValidationStatus.DANGEROUS_ALGORITHM
        result.errors.append("Algorithm 'none' rejected — unsigned tokens are not accepted")
        return result

    decode_opts: dict[str, Any] = {
        "leeway": LEEWAY_SECONDS,
        "algorithms": allowed_algs,
    }
    if expected_audience is not None:
        decode_opts["audience"] = expected_audience
    if expected_issuer is not None:
        decode_opts["issuer"] = expected_issuer

    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            secret_or_pubkey,
            **decode_opts,
        )
    except jwt.ExpiredSignatureError as exc:
        result.status = ValidationStatus.EXPIRED
        result.errors.append(str(exc))
        _try_attach_claims(token, result)
        return result
    except jwt.ImmatureSignatureError as exc:
        result.status = ValidationStatus.NOT_YET_VALID
        result.errors.append(str(exc))
        return result
    except jwt.InvalidSignatureError as exc:
        result.status = ValidationStatus.INVALID_SIGNATURE
        result.errors.append(str(exc))
        return result
    except jwt.InvalidAudienceError as exc:
        result.status = ValidationStatus.AUDIENCE_MISMATCH
        result.errors.append(str(exc))
        return result
    except jwt.InvalidIssuerError as exc:
        result.status = ValidationStatus.ISSUER_MISMATCH
        result.errors.append(str(exc))
        return result
    except jwt.DecodeError as exc:
        result.status = ValidationStatus.MALFORMED
        result.errors.append(str(exc))
        return result
    except jwt.PyJWTError as exc:
        result.status = ValidationStatus.MALFORMED
        result.errors.append(str(exc))
        return result

    claims = _parse_claims(payload)
    result.claims = claims

    now = int(time.time())
    if claims.issued_at is not None and (now - claims.issued_at) > MAX_TOKEN_AGE_SECONDS:
        result.status = ValidationStatus.TOKEN_TOO_OLD
        result.errors.append("Token age exceeds 24-hour hard cap")
        return result

    if required_claims:
        for rc in required_claims:
            if payload.get(rc) is None:
                result.status = ValidationStatus.MISSING_CLAIM
                result.errors.append(f"Required claim '{rc}' is absent")
                return result

    if header.algorithm in DANGEROUS_ALGORITHMS:
        result.warnings.append(
            f"Symmetric algorithm {header.algorithm}: keep secret confidential"
        )

    logger.info("JWT validated fingerprint=%s alg=%s sub=%s", result.fingerprint[:16], header.algorithm, claims.subject)
    return result


def _try_attach_claims(token: str, result: ValidationResult) -> None:
    """Best-effort payload parse after signature failure."""
    try:
        raw = decode_payload_unsafe(token)
        result.claims = _parse_claims(raw)
    except ValueError:
        pass


def load_public_key_from_pem(pem: str) -> str:
    """Return PEM string as-is after basic sanity check.

    Args:
        pem: PEM-encoded public key or certificate.

    Returns:
        Validated PEM string.
    """
    pem = pem.strip()
    if "CERTIFICATE" in pem:
        cert = load_pem_x509_certificate(pem.encode())
        pub: RSAPublicKey = cert.public_key()  # type: ignore[assignment]
        _ = pub  # just validate it loads
    elif "PUBLIC KEY" not in pem:
        raise ValueError("PEM must contain PUBLIC KEY or CERTIFICATE block")
    return pem
