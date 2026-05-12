"""Tests for WebAuthn/FIDO2 Verifier core logic."""

from __future__ import annotations

import base64
import hashlib
import json
import struct

import pytest

from project_42.core import (
    FLAG_UP,
    FLAG_UV,
    FLAG_AT,
    ChallengeStore,
    CredentialStore,
    StoredCredential,
    VerificationStatus,
    WebAuthnVerifier,
    build_sample_auth_data,
    parse_authenticator_data,
)

RP_ID = "example.com"
ORIGIN = "https://example.com"
RP_ID_HASH = hashlib.sha256(RP_ID.encode()).digest()


def _make_verifier() -> WebAuthnVerifier:
    return WebAuthnVerifier(rp_id=RP_ID, origin=ORIGIN)


def _client_data(challenge: str, ctype: str = "webauthn.get") -> bytes:
    return json.dumps({"type": ctype, "challenge": challenge, "origin": ORIGIN}).encode()


class TestParseAuthenticatorData:
    def test_parse_minimal(self) -> None:
        raw = build_sample_auth_data(RP_ID, sign_count=5)
        auth_data = parse_authenticator_data(raw)
        assert auth_data.rp_id_hash == RP_ID_HASH
        assert auth_data.sign_count == 5
        assert auth_data.user_present

    def test_user_verified_flag(self) -> None:
        raw = build_sample_auth_data(RP_ID, flags=FLAG_UP | FLAG_UV)
        auth_data = parse_authenticator_data(raw)
        assert auth_data.user_verified

    def test_up_only_not_uv(self) -> None:
        raw = build_sample_auth_data(RP_ID, flags=FLAG_UP)
        auth_data = parse_authenticator_data(raw)
        assert auth_data.user_present
        assert not auth_data.user_verified

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            parse_authenticator_data(b"\x00" * 10)

    def test_with_attested_credential_data(self) -> None:
        rp_hash = hashlib.sha256(RP_ID.encode()).digest()
        aaguid = b"\x00" * 16
        cred_id = b"\xab" * 16
        cred_id_len = struct.pack(">H", len(cred_id))
        count_bytes = struct.pack(">I", 1)
        raw = rp_hash + bytes([FLAG_UP | FLAG_AT]) + count_bytes + aaguid + cred_id_len + cred_id
        auth_data = parse_authenticator_data(raw)
        assert auth_data.aaguid == aaguid
        assert auth_data.credential_id == cred_id


class TestChallengeStore:
    def test_issue_unique(self) -> None:
        store = ChallengeStore()
        c1 = store.issue()
        c2 = store.issue()
        assert c1 != c2

    def test_consume_valid(self) -> None:
        store = ChallengeStore()
        c = store.issue()
        assert store.consume(c)

    def test_consume_twice_fails(self) -> None:
        store = ChallengeStore()
        c = store.issue()
        store.consume(c)
        assert not store.consume(c)

    def test_consume_unknown_fails(self) -> None:
        store = ChallengeStore()
        assert not store.consume("not-issued")


class TestWebAuthnVerifier:
    def test_valid_client_data(self) -> None:
        v = _make_verifier()
        store = ChallengeStore()
        c = store.issue()
        result = v.verify_client_data(_client_data(c, "webauthn.get"), c, "webauthn.get")
        assert result.ok

    def test_challenge_mismatch(self) -> None:
        v = _make_verifier()
        result = v.verify_client_data(_client_data("wrong", "webauthn.get"), "expected", "webauthn.get")
        assert result.status == VerificationStatus.CHALLENGE_MISMATCH

    def test_origin_mismatch(self) -> None:
        v = _make_verifier()
        store = ChallengeStore()
        c = store.issue()
        data = json.dumps({"type": "webauthn.get", "challenge": c, "origin": "https://evil.com"}).encode()
        result = v.verify_client_data(data, c, "webauthn.get")
        assert result.status == VerificationStatus.ORIGIN_MISMATCH

    def test_wrong_ceremony_type(self) -> None:
        v = _make_verifier()
        store = ChallengeStore()
        c = store.issue()
        result = v.verify_client_data(_client_data(c, "webauthn.create"), c, "webauthn.get")
        assert result.status == VerificationStatus.INVALID_FORMAT

    def test_malformed_client_data(self) -> None:
        v = _make_verifier()
        result = v.verify_client_data(b"not-json", "challenge", "webauthn.get")
        assert result.status == VerificationStatus.INVALID_FORMAT

    def test_valid_auth_data(self) -> None:
        v = _make_verifier()
        raw = build_sample_auth_data(RP_ID, sign_count=5)
        auth_data = parse_authenticator_data(raw)
        result = v.verify_authenticator_data(auth_data, stored_sign_count=4)
        assert result.ok
        assert result.new_sign_count == 5

    def test_rp_id_mismatch(self) -> None:
        v = _make_verifier()
        raw = build_sample_auth_data("other.com", sign_count=1)
        auth_data = parse_authenticator_data(raw)
        result = v.verify_authenticator_data(auth_data)
        assert result.status == VerificationStatus.RP_ID_MISMATCH

    def test_user_not_present(self) -> None:
        v = _make_verifier()
        raw = build_sample_auth_data(RP_ID, flags=0x00)
        auth_data = parse_authenticator_data(raw)
        result = v.verify_authenticator_data(auth_data)
        assert result.status == VerificationStatus.USER_NOT_PRESENT

    def test_user_not_verified_when_required(self) -> None:
        v = _make_verifier()
        raw = build_sample_auth_data(RP_ID, flags=FLAG_UP)
        auth_data = parse_authenticator_data(raw)
        result = v.verify_authenticator_data(auth_data, require_user_verification=True)
        assert result.status == VerificationStatus.USER_NOT_VERIFIED

    def test_sign_counter_replay(self) -> None:
        v = _make_verifier()
        raw = build_sample_auth_data(RP_ID, sign_count=3)
        auth_data = parse_authenticator_data(raw)
        result = v.verify_authenticator_data(auth_data, stored_sign_count=5)
        assert result.status == VerificationStatus.COUNTER_REPLAY


class TestCredentialStore:
    def test_store_and_retrieve(self) -> None:
        store = CredentialStore()
        cred = StoredCredential(
            credential_id="cred-001",
            user_id="alice",
            rp_id=RP_ID,
            sign_count=0,
            public_key_pem="pem",
            aaguid="0" * 32,
        )
        store.store(cred)
        assert store.get("cred-001") == cred

    def test_list_for_user(self) -> None:
        store = CredentialStore()
        for i in range(3):
            store.store(StoredCredential(f"cred-{i}", "alice", RP_ID, 0, "pem", "0" * 32))
        store.store(StoredCredential("cred-bob", "bob", RP_ID, 0, "pem", "0" * 32))
        assert len(store.list_for_user("alice")) == 3

    def test_remove(self) -> None:
        store = CredentialStore()
        store.store(StoredCredential("cred-x", "u", RP_ID, 0, "pem", "0" * 32))
        assert store.remove("cred-x")
        assert store.get("cred-x") is None

    def test_remove_nonexistent(self) -> None:
        store = CredentialStore()
        assert not store.remove("nope")
