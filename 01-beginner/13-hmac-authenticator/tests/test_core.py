"""Unit tests for project_13.core."""

from __future__ import annotations

from pathlib import Path

import pytest

from project_13.core import (
    HMACResult,
    compute_hmac,
    derive_key_from_passphrase,
    sign_file,
    verify_file,
    verify_hmac,
)

_KEY = b"supersecretkey_for_testing_only!!"
_MSG = b"Hello, HMAC world!"


class TestComputeHmac:
    def test_returns_hmac_result(self) -> None:
        r = compute_hmac(_MSG, _KEY)
        assert isinstance(r, HMACResult)

    def test_sha256_hex_length(self) -> None:
        r = compute_hmac(_MSG, _KEY, algorithm="sha256")
        assert len(r.digest) == 64

    def test_sha512_hex_length(self) -> None:
        r = compute_hmac(_MSG, _KEY, algorithm="sha512")
        assert len(r.digest) == 128

    def test_digest_is_hex(self) -> None:
        r = compute_hmac(_MSG, _KEY)
        int(r.digest, 16)  # raises if not valid hex

    def test_same_inputs_same_output(self) -> None:
        r1 = compute_hmac(_MSG, _KEY)
        r2 = compute_hmac(_MSG, _KEY)
        assert r1.digest == r2.digest

    def test_different_keys_different_digests(self) -> None:
        r1 = compute_hmac(_MSG, _KEY)
        r2 = compute_hmac(_MSG, b"otherkey_for_testing_purposes!!")
        assert r1.digest != r2.digest

    def test_different_messages_different_digests(self) -> None:
        r1 = compute_hmac(b"msg1", _KEY)
        r2 = compute_hmac(b"msg2", _KEY)
        assert r1.digest != r2.digest

    def test_unsupported_algorithm_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported"):
            compute_hmac(_MSG, _KEY, algorithm="md5")

    def test_empty_key_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            compute_hmac(_MSG, b"")


class TestVerifyHmac:
    def test_valid_digest_returns_true(self) -> None:
        r = compute_hmac(_MSG, _KEY)
        assert verify_hmac(_MSG, _KEY, r.digest) is True

    def test_wrong_digest_returns_false(self) -> None:
        assert verify_hmac(_MSG, _KEY, "deadbeef" * 8) is False

    def test_case_insensitive(self) -> None:
        r = compute_hmac(_MSG, _KEY)
        assert verify_hmac(_MSG, _KEY, r.digest.upper()) is True

    def test_tampered_message_fails(self) -> None:
        r = compute_hmac(_MSG, _KEY)
        assert verify_hmac(b"tampered", _KEY, r.digest) is False


class TestSignFile:
    def test_returns_result(self, tmp_path: Path) -> None:
        f = tmp_path / "data.txt"
        f.write_bytes(_MSG)
        r = sign_file(f, _KEY)
        assert isinstance(r, HMACResult)

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            sign_file(tmp_path / "nope.txt", _KEY)


class TestVerifyFile:
    def test_valid_signature(self, tmp_path: Path) -> None:
        f = tmp_path / "data.txt"
        f.write_bytes(_MSG)
        r = sign_file(f, _KEY)
        assert verify_file(f, _KEY, r.digest) is True

    def test_modified_file_fails(self, tmp_path: Path) -> None:
        f = tmp_path / "data.txt"
        f.write_bytes(_MSG)
        r = sign_file(f, _KEY)
        f.write_bytes(b"tampered content")
        assert verify_file(f, _KEY, r.digest) is False

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            verify_file(tmp_path / "nope.txt", _KEY, "abc")


class TestDeriveKey:
    def test_returns_bytes(self) -> None:
        k = derive_key_from_passphrase("mypassword")
        assert isinstance(k, bytes)

    def test_sha256_gives_32_bytes(self) -> None:
        k = derive_key_from_passphrase("mypassword", algorithm="sha256")
        assert len(k) == 32

    def test_sha512_gives_64_bytes(self) -> None:
        k = derive_key_from_passphrase("mypassword", algorithm="sha512")
        assert len(k) == 64
