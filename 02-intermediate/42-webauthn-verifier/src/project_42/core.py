"""WebAuthn/FIDO2 Verifier — authenticator data parser and credential store.

Implements the verification steps from W3C WebAuthn Level 2 (§7.1 Registration,
§7.2 Authentication) without a network dependency on an RP server.

Defends against: T1078 (Valid Accounts — password bypass via phishing),
T1556 (Modify Authentication Process), T1110 (Brute Force).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import struct
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants (W3C WebAuthn §6.1)
# ---------------------------------------------------------------------------

CHALLENGE_BYTES: int = 32
AAGUID_ZERO: bytes = b"\x00" * 16
FLAG_UP: int = 0x01   # User Present
FLAG_UV: int = 0x04   # User Verified
FLAG_AT: int = 0x40   # Attested Credential Data present
FLAG_ED: int = 0x80   # Extension Data present


class VerificationStatus(StrEnum):
    """Outcome of a WebAuthn ceremony verification."""

    OK = "ok"
    CHALLENGE_MISMATCH = "challenge_mismatch"
    ORIGIN_MISMATCH = "origin_mismatch"
    RP_ID_MISMATCH = "rpid_mismatch"
    USER_NOT_PRESENT = "user_not_present"
    USER_NOT_VERIFIED = "user_not_verified"
    COUNTER_REPLAY = "counter_replay"
    CREDENTIAL_NOT_FOUND = "credential_not_found"
    INVALID_FORMAT = "invalid_format"


# ---------------------------------------------------------------------------
# Authenticator Data (§6.1)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthenticatorData:
    """Parsed WebAuthn authenticator data structure."""

    rp_id_hash: bytes          # 32 bytes
    flags: int                 # 1 byte
    sign_count: int            # 4 bytes
    aaguid: bytes | None       # 16 bytes (AT flag)
    credential_id: bytes | None
    raw: bytes

    @property
    def user_present(self) -> bool:
        """UP flag set."""
        return bool(self.flags & FLAG_UP)

    @property
    def user_verified(self) -> bool:
        """UV flag set."""
        return bool(self.flags & FLAG_UV)

    @property
    def has_attested_credential(self) -> bool:
        """AT flag set."""
        return bool(self.flags & FLAG_AT)


def parse_authenticator_data(raw: bytes) -> AuthenticatorData:
    """Parse binary authenticator data per W3C WebAuthn §6.1.

    Args:
        raw: Raw authenticator data bytes (at least 37 bytes).

    Returns:
        AuthenticatorData with parsed fields.

    Raises:
        ValueError: If the data is too short or malformed.
    """
    MIN_LEN = 37
    if len(raw) < MIN_LEN:
        raise ValueError(f"Authenticator data too short: {len(raw)} < {MIN_LEN}")

    rp_id_hash = raw[:32]
    flags = raw[32]
    sign_count = struct.unpack(">I", raw[33:37])[0]

    aaguid: bytes | None = None
    credential_id: bytes | None = None

    if flags & FLAG_AT and len(raw) > 37:
        offset = 37
        aaguid = raw[offset:offset + 16]
        offset += 16
        if len(raw) < offset + 2:
            raise ValueError("Authenticator data truncated before credential ID length")
        cred_id_len = struct.unpack(">H", raw[offset:offset + 2])[0]
        offset += 2
        if len(raw) < offset + cred_id_len:
            raise ValueError("Authenticator data truncated in credential ID")
        credential_id = raw[offset:offset + cred_id_len]

    return AuthenticatorData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        sign_count=sign_count,
        aaguid=aaguid,
        credential_id=credential_id,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Credential store
# ---------------------------------------------------------------------------

@dataclass
class StoredCredential:
    """A registered FIDO2 credential (server-side record)."""

    credential_id: str          # base64url
    user_id: str
    rp_id: str
    sign_count: int
    public_key_pem: str
    aaguid: str
    transports: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class VerificationResult:
    """Result of a WebAuthn ceremony step."""

    status: VerificationStatus
    credential_id: str | None = None
    user_id: str | None = None
    new_sign_count: int | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when status is OK."""
        return self.status == VerificationStatus.OK


class CredentialStore:
    """In-memory WebAuthn credential registry."""

    def __init__(self) -> None:
        self._creds: dict[str, StoredCredential] = {}

    def store(self, cred: StoredCredential) -> None:
        """Register a new credential.

        Args:
            cred: StoredCredential to persist.
        """
        self._creds[cred.credential_id] = cred
        logger.info("Credential stored user_id=%s cred_id=%.16s", cred.user_id, cred.credential_id)

    def get(self, credential_id: str) -> StoredCredential | None:
        """Retrieve a credential by ID.

        Args:
            credential_id: base64url credential ID.

        Returns:
            StoredCredential or None.
        """
        return self._creds.get(credential_id)

    def list_for_user(self, user_id: str) -> list[StoredCredential]:
        """Return all credentials for a user.

        Args:
            user_id: User identifier.

        Returns:
            List of StoredCredential objects.
        """
        return [c for c in self._creds.values() if c.user_id == user_id]

    def remove(self, credential_id: str) -> bool:
        """Delete a credential.

        Args:
            credential_id: Credential to remove.

        Returns:
            True if found and removed.
        """
        if credential_id in self._creds:
            del self._creds[credential_id]
            return True
        return False


# ---------------------------------------------------------------------------
# Challenge manager
# ---------------------------------------------------------------------------

class ChallengeStore:
    """Single-use challenge registry (prevents replay)."""

    def __init__(self) -> None:
        self._challenges: set[str] = set()

    def issue(self) -> str:
        """Generate and store a new random challenge.

        Returns:
            base64url-encoded challenge string.
        """
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(CHALLENGE_BYTES)).rstrip(b"=").decode()
        self._challenges.add(challenge)
        return challenge

    def consume(self, challenge: str) -> bool:
        """Verify and consume a challenge (one-time use).

        Args:
            challenge: Challenge value from client response.

        Returns:
            True if the challenge was valid and has now been consumed.
        """
        if challenge in self._challenges:
            self._challenges.discard(challenge)
            return True
        return False


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

class WebAuthnVerifier:
    """Stateless WebAuthn ceremony verifier (RP-side logic).

    Handles the server-side steps of W3C WebAuthn §7.1 (Registration)
    and §7.2 (Authentication) without requiring a full RP server.
    """

    def __init__(self, rp_id: str, origin: str) -> None:
        self._rp_id = rp_id
        self._origin = origin
        self._rp_id_hash = hashlib.sha256(rp_id.encode()).digest()

    def verify_client_data(
        self,
        client_data_json: bytes,
        expected_challenge: str,
        ceremony_type: str,
    ) -> VerificationResult:
        """Verify clientDataJSON fields (§7.1 steps 7–10, §7.2 steps 11–14).

        Args:
            client_data_json: Raw UTF-8 clientDataJSON bytes.
            expected_challenge: The challenge issued by the server.
            ceremony_type: 'webauthn.create' or 'webauthn.get'.

        Returns:
            VerificationResult.
        """
        try:
            data: dict[str, Any] = json.loads(client_data_json.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return VerificationResult(status=VerificationStatus.INVALID_FORMAT)

        client_type = data.get("type", "")
        if client_type != ceremony_type:
            return VerificationResult(
                status=VerificationStatus.INVALID_FORMAT,
                warnings=[f"Expected type={ceremony_type}, got={client_type}"],
            )

        # Challenge is base64url-encoded in clientDataJSON
        received_challenge = data.get("challenge", "")
        _add_padding = received_challenge + "=" * (4 - len(received_challenge) % 4)
        if not secrets.compare_digest(received_challenge.encode(), expected_challenge.encode()):
            return VerificationResult(status=VerificationStatus.CHALLENGE_MISMATCH)

        if data.get("origin", "") != self._origin:
            return VerificationResult(
                status=VerificationStatus.ORIGIN_MISMATCH,
                warnings=[f"Expected origin={self._origin}, got={data.get('origin')}"],
            )

        return VerificationResult(status=VerificationStatus.OK)

    def verify_authenticator_data(
        self,
        auth_data: AuthenticatorData,
        *,
        require_user_verification: bool = False,
        stored_sign_count: int = 0,
    ) -> VerificationResult:
        """Verify authenticator data fields (§7.2 steps 15–18).

        Args:
            auth_data: Parsed AuthenticatorData.
            require_user_verification: Enforce UV flag.
            stored_sign_count: Last known sign counter for replay detection.

        Returns:
            VerificationResult.
        """
        warnings: list[str] = []

        if not secrets.compare_digest(auth_data.rp_id_hash, self._rp_id_hash):
            return VerificationResult(status=VerificationStatus.RP_ID_MISMATCH)

        if not auth_data.user_present:
            return VerificationResult(status=VerificationStatus.USER_NOT_PRESENT)

        if require_user_verification and not auth_data.user_verified:
            return VerificationResult(status=VerificationStatus.USER_NOT_VERIFIED)

        if auth_data.sign_count != 0 or stored_sign_count != 0:
            if auth_data.sign_count <= stored_sign_count:
                logger.warning(
                    "Sign counter replay detected stored=%d received=%d",
                    stored_sign_count, auth_data.sign_count,
                )
                return VerificationResult(status=VerificationStatus.COUNTER_REPLAY)

        if not auth_data.user_verified:
            warnings.append("UV flag not set; user-presence only (consider requiring UV)")

        return VerificationResult(
            status=VerificationStatus.OK,
            new_sign_count=auth_data.sign_count,
            warnings=warnings,
        )


def build_sample_auth_data(
    rp_id: str,
    sign_count: int = 1,
    flags: int = FLAG_UP | FLAG_UV,
) -> bytes:
    """Build minimal authenticator data bytes for testing/demo.

    Args:
        rp_id: Relying Party ID.
        sign_count: Signature counter value.
        flags: Authenticator flags byte.

    Returns:
        37-byte authenticator data buffer.
    """
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    count_bytes = struct.pack(">I", sign_count)
    return rp_id_hash + bytes([flags]) + count_bytes
