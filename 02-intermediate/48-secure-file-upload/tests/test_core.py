"""Tests for project 48 core module."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from project_48.core import (
    DEFAULT_MAX_BYTES,
    DisallowedMimeTypeError,
    FileTooLargeError,
    MagicMismatchError,
    UnsafeFilenameError,
    UploadStorage,
    UploadValidator,
)

PNG_MAGIC = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
PDF_MAGIC = b"%PDF-1.4\n" + b"\x00" * 100
JPEG_MAGIC = b"\xff\xd8\xff\xe0" + b"\x00" * 100


class TestUploadValidator:
    def setup_method(self) -> None:
        self.v = UploadValidator()

    def test_valid_filename(self) -> None:
        assert self.v.validate_filename("photo.jpg") == "photo.jpg"

    def test_strips_directory_component(self) -> None:
        result = self.v.validate_filename("../../etc/passwd")
        assert result == "passwd"

    def test_empty_filename_raises(self) -> None:
        with pytest.raises(UnsafeFilenameError):
            self.v.validate_filename("")

    def test_dotdot_filename_raises(self) -> None:
        with pytest.raises(UnsafeFilenameError):
            self.v.validate_filename("..")

    def test_unsafe_chars_raises(self) -> None:
        with pytest.raises(UnsafeFilenameError):
            self.v.validate_filename("file;rm -rf /;.txt")

    def test_size_ok(self) -> None:
        self.v.validate_size(b"x" * 100)

    def test_size_too_large(self) -> None:
        with pytest.raises(FileTooLargeError):
            UploadValidator(max_bytes=10).validate_size(b"x" * 11)

    def test_valid_png(self) -> None:
        mime = self.v.validate("image.png", PNG_MAGIC)
        assert mime == "image/png"

    def test_valid_pdf(self) -> None:
        mime = self.v.validate("document.pdf", PDF_MAGIC)
        assert mime == "application/pdf"

    def test_disallowed_mime(self) -> None:
        with pytest.raises(DisallowedMimeTypeError):
            self.v.validate("script.exe", b"MZ\x90\x00" + b"\x00" * 100)

    def test_magic_mismatch(self) -> None:
        with pytest.raises(MagicMismatchError):
            self.v.validate("image.png", b"GIF89a" + b"\x00" * 100)


class TestUploadStorage:
    def test_store_and_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = UploadStorage(storage_root=Path(tmp))
            result = storage.store("photo.png", PNG_MAGIC)
            assert result.mime_type == "image/png"
            assert result.size_bytes == len(PNG_MAGIC)
            assert len(result.sha256) == 64
            assert Path(result.storage_path).exists()

    def test_stored_file_permissions(self) -> None:
        import stat
        with tempfile.TemporaryDirectory() as tmp:
            storage = UploadStorage(storage_root=Path(tmp))
            result = storage.store("photo.png", PNG_MAGIC)
            mode = Path(result.storage_path).stat().st_mode
            assert not (mode & stat.S_IRGRP), "Group read should not be set"
            assert not (mode & stat.S_IROTH), "Other read should not be set"

    def test_delete_existing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = UploadStorage(storage_root=Path(tmp))
            result = storage.store("photo.png", PNG_MAGIC)
            deleted = storage.delete(result.stored_name)
            assert deleted is True
            assert not Path(result.storage_path).exists()

    def test_delete_nonexistent_returns_false(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = UploadStorage(storage_root=Path(tmp))
            assert storage.delete("does-not-exist.png") is False
