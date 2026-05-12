"""Unit tests for project_08.core."""

from __future__ import annotations

from pathlib import Path

import pytest

from project_08.core import (
    MAGIC,
    MAGIC_LEN,
    DecryptionError,
    decrypt_file,
    encrypt_file,
)

_PASSWORD = "test-passphrase-2024"


class TestEncryptFile:
    def test_creates_output_file(self, tmp_path: Path) -> None:
        src = tmp_path / "plain.txt"
        src.write_bytes(b"Hello, secret world!")
        dst = tmp_path / "plain.txt.enc"
        encrypt_file(src, dst, _PASSWORD)
        assert dst.exists()

    def test_output_starts_with_magic(self, tmp_path: Path) -> None:
        src = tmp_path / "data.bin"
        src.write_bytes(b"test data")
        dst = tmp_path / "data.bin.enc"
        encrypt_file(src, dst, _PASSWORD)
        raw = dst.read_bytes()
        assert raw[:MAGIC_LEN] == MAGIC

    def test_output_larger_than_input(self, tmp_path: Path) -> None:
        src = tmp_path / "plain.txt"
        src.write_bytes(b"hello")
        dst = tmp_path / "plain.txt.enc"
        encrypt_file(src, dst, _PASSWORD)
        assert dst.stat().st_size > src.stat().st_size

    def test_missing_src_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            encrypt_file(tmp_path / "no.txt", tmp_path / "out.enc", _PASSWORD)

    def test_directory_src_raises(self, tmp_path: Path) -> None:
        with pytest.raises(IsADirectoryError):
            encrypt_file(tmp_path, tmp_path / "out.enc", _PASSWORD)

    def test_different_passwords_produce_different_output(self, tmp_path: Path) -> None:
        src = tmp_path / "plain.txt"
        src.write_bytes(b"deterministic test")
        dst1 = tmp_path / "enc1.enc"
        dst2 = tmp_path / "enc2.enc"
        encrypt_file(src, dst1, "password1")
        encrypt_file(src, dst2, "password2")
        assert dst1.read_bytes() != dst2.read_bytes()

    def test_same_file_twice_produces_different_ciphertext(self, tmp_path: Path) -> None:
        src = tmp_path / "plain.txt"
        src.write_bytes(b"nonce randomness test")
        dst1 = tmp_path / "enc1.enc"
        dst2 = tmp_path / "enc2.enc"
        encrypt_file(src, dst1, _PASSWORD)
        encrypt_file(src, dst2, _PASSWORD)
        assert dst1.read_bytes() != dst2.read_bytes()


class TestDecryptFile:
    def test_roundtrip(self, tmp_path: Path) -> None:
        plaintext = b"This is the secret message."
        src = tmp_path / "plain.txt"
        src.write_bytes(plaintext)
        enc = tmp_path / "plain.enc"
        dec = tmp_path / "plain.dec"
        encrypt_file(src, enc, _PASSWORD)
        decrypt_file(enc, dec, _PASSWORD)
        assert dec.read_bytes() == plaintext

    def test_wrong_password_raises(self, tmp_path: Path) -> None:
        src = tmp_path / "plain.txt"
        src.write_bytes(b"data")
        enc = tmp_path / "plain.enc"
        dec = tmp_path / "plain.dec"
        encrypt_file(src, enc, _PASSWORD)
        with pytest.raises(DecryptionError):
            decrypt_file(enc, dec, "wrong-password")

    def test_truncated_file_raises(self, tmp_path: Path) -> None:
        enc = tmp_path / "bad.enc"
        enc.write_bytes(MAGIC + b"\x00" * 10)
        with pytest.raises(ValueError):
            decrypt_file(enc, tmp_path / "out.txt", _PASSWORD)

    def test_bad_magic_raises(self, tmp_path: Path) -> None:
        enc = tmp_path / "bad.enc"
        enc.write_bytes(b"XXXX" + b"\x00" * 100)
        with pytest.raises(ValueError, match="magic"):
            decrypt_file(enc, tmp_path / "out.txt", _PASSWORD)

    def test_missing_encrypted_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            decrypt_file(tmp_path / "no.enc", tmp_path / "out.txt", _PASSWORD)

    def test_tampered_ciphertext_raises(self, tmp_path: Path) -> None:
        src = tmp_path / "plain.txt"
        src.write_bytes(b"sensitive data here")
        enc = tmp_path / "plain.enc"
        decrypt_out = tmp_path / "plain.dec"
        encrypt_file(src, enc, _PASSWORD)
        raw = bytearray(enc.read_bytes())
        # Flip a bit in the ciphertext portion
        raw[-5] ^= 0xFF
        enc.write_bytes(bytes(raw))
        with pytest.raises(DecryptionError):
            decrypt_file(enc, decrypt_out, _PASSWORD)

    def test_empty_file_roundtrip(self, tmp_path: Path) -> None:
        src = tmp_path / "empty.txt"
        src.write_bytes(b"")
        enc = tmp_path / "empty.enc"
        dec = tmp_path / "empty.dec"
        encrypt_file(src, enc, _PASSWORD)
        decrypt_file(enc, dec, _PASSWORD)
        assert dec.read_bytes() == b""
