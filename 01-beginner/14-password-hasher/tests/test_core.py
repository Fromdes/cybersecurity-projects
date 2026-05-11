"""Unit tests for project_14.core."""

from __future__ import annotations

import pytest

from project_14.core import (
    HashAlgorithm,
    HashResult,
    hash_password,
    needs_rehash,
    verify_password,
)

_PASSWORD = "correct-horse-battery-staple"
_WRONG = "wrong-password"


class TestHashPassword:
    def test_returns_hash_result(self) -> None:
        r = hash_password(_PASSWORD)
        assert isinstance(r, HashResult)

    def test_argon2id_phc_format(self) -> None:
        r = hash_password(_PASSWORD, algorithm=HashAlgorithm.ARGON2ID)
        assert r.encoded.startswith("$argon2id$")

    def test_pbkdf2_salt_colon_dk(self) -> None:
        r = hash_password(_PASSWORD, algorithm=HashAlgorithm.PBKDF2)
        parts = r.encoded.split(":")
        assert len(parts) == 2

    def test_unique_hashes(self) -> None:
        r1 = hash_password(_PASSWORD)
        r2 = hash_password(_PASSWORD)
        assert r1.encoded != r2.encoded  # different salts

    def test_empty_password_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            hash_password("")


class TestVerifyPassword:
    def test_argon2id_correct_password(self) -> None:
        r = hash_password(_PASSWORD, algorithm=HashAlgorithm.ARGON2ID)
        assert verify_password(_PASSWORD, r.encoded, algorithm=HashAlgorithm.ARGON2ID)

    def test_argon2id_wrong_password(self) -> None:
        r = hash_password(_PASSWORD, algorithm=HashAlgorithm.ARGON2ID)
        assert not verify_password(_WRONG, r.encoded, algorithm=HashAlgorithm.ARGON2ID)

    def test_pbkdf2_correct_password(self) -> None:
        r = hash_password(_PASSWORD, algorithm=HashAlgorithm.PBKDF2)
        assert verify_password(_PASSWORD, r.encoded, algorithm=HashAlgorithm.PBKDF2)

    def test_pbkdf2_wrong_password(self) -> None:
        r = hash_password(_PASSWORD, algorithm=HashAlgorithm.PBKDF2)
        assert not verify_password(_WRONG, r.encoded, algorithm=HashAlgorithm.PBKDF2)

    def test_pbkdf2_malformed_hash_returns_false(self) -> None:
        assert not verify_password(_PASSWORD, "notahash", algorithm=HashAlgorithm.PBKDF2)

    def test_argon2id_invalid_hash_returns_false(self) -> None:
        assert not verify_password(_PASSWORD, "baddata", algorithm=HashAlgorithm.ARGON2ID)


class TestNeedsRehash:
    def test_current_params_no_rehash(self) -> None:
        r = hash_password(_PASSWORD, algorithm=HashAlgorithm.ARGON2ID)
        assert needs_rehash(r.encoded) is False
