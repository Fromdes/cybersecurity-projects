"""Unit tests for project_09.core."""

from __future__ import annotations

from pathlib import Path

import pytest

from project_09.core import (
    SignatureVerificationError,
    generate_key_pair,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
    sign_file,
    verify_file,
)

_PASSWORD = "test-rsa-password-2024"


@pytest.fixture(scope="module")
def key_pair() -> tuple[object, object]:
    return generate_key_pair()


class TestGenerateKeyPair:
    def test_returns_two_keys(self) -> None:
        private_key, public_key = generate_key_pair()
        assert private_key is not None
        assert public_key is not None

    def test_key_size(self) -> None:
        from project_09.core import RSA_KEY_SIZE
        private_key, _ = generate_key_pair()
        assert private_key.key_size == RSA_KEY_SIZE


class TestSaveLoadPrivateKey:
    def test_roundtrip(self, tmp_path: Path) -> None:
        private_key, _ = generate_key_pair()
        path = tmp_path / "private.pem"
        save_private_key(private_key, path, _PASSWORD)
        loaded = load_private_key(path, _PASSWORD)
        assert loaded.key_size == private_key.key_size

    def test_file_is_pem_format(self, tmp_path: Path) -> None:
        private_key, _ = generate_key_pair()
        path = tmp_path / "private.pem"
        save_private_key(private_key, path, _PASSWORD)
        assert b"BEGIN ENCRYPTED PRIVATE KEY" in path.read_bytes()

    def test_wrong_password_raises(self, tmp_path: Path) -> None:
        private_key, _ = generate_key_pair()
        path = tmp_path / "private.pem"
        save_private_key(private_key, path, _PASSWORD)
        with pytest.raises(ValueError):
            load_private_key(path, "wrong-password")

    def test_empty_password_raises(self, tmp_path: Path) -> None:
        private_key, _ = generate_key_pair()
        path = tmp_path / "private.pem"
        with pytest.raises(ValueError, match="must not be empty"):
            save_private_key(private_key, path, "")

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_private_key(tmp_path / "no.pem", _PASSWORD)


class TestSaveLoadPublicKey:
    def test_roundtrip(self, tmp_path: Path) -> None:
        _, public_key = generate_key_pair()
        path = tmp_path / "public.pem"
        save_public_key(public_key, path)
        loaded = load_public_key(path)
        assert loaded.key_size == public_key.key_size

    def test_file_is_pem_format(self, tmp_path: Path) -> None:
        _, public_key = generate_key_pair()
        path = tmp_path / "public.pem"
        save_public_key(public_key, path)
        assert b"BEGIN PUBLIC KEY" in path.read_bytes()

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_public_key(tmp_path / "no.pem")


class TestSignVerify:
    def test_sign_and_verify(self, tmp_path: Path) -> None:
        private_key, public_key = generate_key_pair()
        f = tmp_path / "document.txt"
        f.write_bytes(b"Important document content")
        signature = sign_file(f, private_key)
        assert verify_file(f, signature, public_key) is True

    def test_verify_tampered_file_raises(self, tmp_path: Path) -> None:
        private_key, public_key = generate_key_pair()
        f = tmp_path / "doc.txt"
        f.write_bytes(b"Original content")
        signature = sign_file(f, private_key)
        f.write_bytes(b"Tampered content!")
        with pytest.raises(SignatureVerificationError):
            verify_file(f, signature, public_key)

    def test_verify_wrong_signature_raises(self, tmp_path: Path) -> None:
        private_key, public_key = generate_key_pair()
        f = tmp_path / "doc.txt"
        f.write_bytes(b"document")
        with pytest.raises(SignatureVerificationError):
            verify_file(f, b"\x00" * 512, public_key)

    def test_sign_missing_file_raises(self, tmp_path: Path) -> None:
        private_key, _ = generate_key_pair()
        with pytest.raises(FileNotFoundError):
            sign_file(tmp_path / "no.txt", private_key)

    def test_different_keys_fail_verification(self, tmp_path: Path) -> None:
        pk1, pub1 = generate_key_pair()
        pk2, pub2 = generate_key_pair()
        f = tmp_path / "doc.txt"
        f.write_bytes(b"document data")
        signature = sign_file(f, pk1)
        with pytest.raises(SignatureVerificationError):
            verify_file(f, signature, pub2)
