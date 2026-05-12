"""Encrypted notes storage using AES-256-GCM and Argon2id key derivation."""
from __future__ import annotations

import json
import logging
import secrets
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger(__name__)

KEY_LEN: int = 32
SALT_LEN: int = 16
NONCE_LEN: int = 12

ARGON2_TIME_COST: int = 3
ARGON2_MEMORY_COST: int = 65536
ARGON2_PARALLELISM: int = 1


@dataclass
class Note:
    """A single encrypted note record."""

    id: str
    title: str
    body: str
    created_at: str
    updated_at: str

    @staticmethod
    def new(title: str, body: str) -> Note:
        """Create a new note with generated ID and timestamps."""
        now = datetime.now(tz=UTC).isoformat()
        return Note(id=str(uuid.uuid4()), title=title, body=body,
                    created_at=now, updated_at=now)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from *password* using Argon2id.

    Args:
        password: User-supplied master password.
        salt: 16-byte random salt.

    Returns:
        32-byte derived key.
    """
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


class NotesStore:
    """Encrypted notes store backed by a single AES-256-GCM file.

    Args:
        path: Path to the encrypted notes file.
        password: Master password for key derivation.
    """

    def __init__(self, path: Path, password: str) -> None:
        self._path = path
        self._password = password
        self._salt: bytes = b""
        self._notes: list[Note] = []
        if path.exists():
            self._load()
        else:
            self._salt = secrets.token_bytes(SALT_LEN)

    def _load(self) -> None:
        """Decrypt and load notes from disk."""
        raw = self._path.read_bytes()
        salt = raw[:SALT_LEN]
        nonce = raw[SALT_LEN: SALT_LEN + NONCE_LEN]
        ciphertext = raw[SALT_LEN + NONCE_LEN:]
        key = derive_key(self._password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        data = json.loads(plaintext.decode())
        self._salt = salt
        self._notes = [Note(**n) for n in data["notes"]]

    def save(self) -> None:
        """Encrypt and persist current notes to disk."""
        key = derive_key(self._password, self._salt)
        nonce = secrets.token_bytes(NONCE_LEN)
        aesgcm = AESGCM(key)
        data = json.dumps({"notes": [asdict(n) for n in self._notes]})
        ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
        self._path.write_bytes(self._salt + nonce + ciphertext)
        self._path.chmod(0o600)

    def add_note(self, title: str, body: str) -> Note:
        """Create and persist a new note.

        Args:
            title: Short note title.
            body: Note content.

        Returns:
            The created :class:`Note`.

        Raises:
            ValueError: If title is empty.
        """
        if not title.strip():
            raise ValueError("title must not be empty")
        note = Note.new(title, body)
        self._notes.append(note)
        self.save()
        return note

    def get_note(self, note_id: str) -> Note:
        """Retrieve a note by ID.

        Args:
            note_id: UUID string of the note.

        Returns:
            Matching :class:`Note`.

        Raises:
            KeyError: If no note with *note_id* exists.
        """
        for note in self._notes:
            if note.id == note_id:
                return note
        raise KeyError(f"Note not found: {note_id}")

    def list_notes(self) -> list[Note]:
        """Return all notes (no body content — titles only for listing).

        Returns:
            Shallow copies with body omitted for safe listing.
        """
        return list(self._notes)

    def delete_note(self, note_id: str) -> None:
        """Delete a note by ID and persist.

        Args:
            note_id: UUID of the note to delete.

        Raises:
            KeyError: If no note with *note_id* exists.
        """
        original_len = len(self._notes)
        self._notes = [n for n in self._notes if n.id != note_id]
        if len(self._notes) == original_len:
            raise KeyError(f"Note not found: {note_id}")
        self.save()

    def update_note(self, note_id: str, title: str | None = None, body: str | None = None) -> Note:
        """Update title and/or body of an existing note.

        Args:
            note_id: UUID of the note to update.
            title: New title (None = keep existing).
            body: New body (None = keep existing).

        Returns:
            Updated :class:`Note`.

        Raises:
            KeyError: If note not found.
        """
        note = self.get_note(note_id)
        idx = self._notes.index(note)
        updated = Note(
            id=note.id,
            title=title if title is not None else note.title,
            body=body if body is not None else note.body,
            created_at=note.created_at,
            updated_at=datetime.now(tz=UTC).isoformat(),
        )
        self._notes[idx] = updated
        self.save()
        return updated
