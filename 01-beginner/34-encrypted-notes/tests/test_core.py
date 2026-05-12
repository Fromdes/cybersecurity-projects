"""Tests for project_34.core — Encrypted Notes CLI."""
from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from project_34.core import Note, NotesStore, derive_key


class TestDeriveKey:
    def test_returns_32_bytes(self) -> None:
        key = derive_key("password", b"0123456789abcdef")
        assert len(key) == 32

    def test_different_salts_different_keys(self) -> None:
        k1 = derive_key("password", b"0123456789abcdef")
        k2 = derive_key("password", b"fedcba9876543210")
        assert k1 != k2

    def test_different_passwords_different_keys(self) -> None:
        salt = b"0123456789abcdef"
        k1 = derive_key("password1", salt)
        k2 = derive_key("password2", salt)
        assert k1 != k2

    def test_deterministic(self) -> None:
        salt = b"0123456789abcdef"
        assert derive_key("pw", salt) == derive_key("pw", salt)


class TestNote:
    def test_new_generates_uuid(self) -> None:
        n = Note.new("title", "body")
        assert len(n.id) == 36
        assert n.id.count("-") == 4

    def test_new_sets_timestamps(self) -> None:
        n = Note.new("title", "body")
        assert n.created_at
        assert n.updated_at


class TestNotesStore:
    def test_add_and_retrieve(self, tmp_path: Path) -> None:
        store = NotesStore(tmp_path / "notes.enc", "secret")
        note = store.add_note("My Title", "My Body")
        retrieved = store.get_note(note.id)
        assert retrieved.title == "My Title"
        assert retrieved.body == "My Body"

    def test_persist_and_reload(self, tmp_path: Path) -> None:
        path = tmp_path / "notes.enc"
        store1 = NotesStore(path, "secret")
        note = store1.add_note("Persisted", "Content")
        store2 = NotesStore(path, "secret")
        loaded = store2.get_note(note.id)
        assert loaded.title == "Persisted"

    def test_wrong_password_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "notes.enc"
        store1 = NotesStore(path, "correct")
        store1.add_note("x", "y")
        with pytest.raises(InvalidTag):
            NotesStore(path, "wrong")

    def test_list_notes(self, tmp_path: Path) -> None:
        store = NotesStore(tmp_path / "notes.enc", "secret")
        store.add_note("A", "")
        store.add_note("B", "")
        notes = store.list_notes()
        assert len(notes) == 2

    def test_delete_note(self, tmp_path: Path) -> None:
        store = NotesStore(tmp_path / "notes.enc", "secret")
        note = store.add_note("ToDelete", "")
        store.delete_note(note.id)
        assert len(store.list_notes()) == 0

    def test_delete_nonexistent_raises(self, tmp_path: Path) -> None:
        store = NotesStore(tmp_path / "notes.enc", "secret")
        with pytest.raises(KeyError):
            store.delete_note("nonexistent-id")

    def test_get_nonexistent_raises(self, tmp_path: Path) -> None:
        store = NotesStore(tmp_path / "notes.enc", "secret")
        with pytest.raises(KeyError):
            store.get_note("nonexistent-id")

    def test_update_note(self, tmp_path: Path) -> None:
        store = NotesStore(tmp_path / "notes.enc", "secret")
        note = store.add_note("Original", "Old body")
        updated = store.update_note(note.id, title="New Title", body="New body")
        assert updated.title == "New Title"
        assert updated.body == "New body"
        assert updated.created_at == note.created_at

    def test_update_only_title(self, tmp_path: Path) -> None:
        store = NotesStore(tmp_path / "notes.enc", "secret")
        note = store.add_note("Title", "Body")
        updated = store.update_note(note.id, title="New Title")
        assert updated.body == "Body"

    def test_empty_title_raises(self, tmp_path: Path) -> None:
        store = NotesStore(tmp_path / "notes.enc", "secret")
        with pytest.raises(ValueError, match="empty"):
            store.add_note("", "body")

    def test_file_mode_is_600(self, tmp_path: Path) -> None:
        path = tmp_path / "notes.enc"
        store = NotesStore(path, "secret")
        store.add_note("x", "y")
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600
