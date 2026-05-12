"""Password vault core: encrypted storage with search and password generation."""
from __future__ import annotations

import json
import logging
import secrets
import string
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
DEFAULT_PASSWORD_LEN: int = 24

ARGON2_TIME_COST: int = 3
ARGON2_MEMORY_COST: int = 65536
ARGON2_PARALLELISM: int = 1

PASSWORD_CHARS: str = (
    string.ascii_uppercase + string.ascii_lowercase + string.digits + "!@#$%^&*()-_=+"
)


@dataclass
class VaultEntry:
    """A stored credential record."""

    id: str
    site: str
    username: str
    password: str
    notes: str
    created_at: str
    modified_at: str

    @staticmethod
    def new(site: str, username: str, password: str, notes: str = "") -> VaultEntry:
        """Create a new VaultEntry with generated ID and timestamps."""
        now = datetime.now(tz=UTC).isoformat()
        return VaultEntry(
            id=str(uuid.uuid4()), site=site, username=username,
            password=password, notes=notes,
            created_at=now, modified_at=now,
        )


def generate_password(length: int = DEFAULT_PASSWORD_LEN) -> str:
    """Generate a cryptographically secure random password.

    Args:
        length: Number of characters (minimum 8).

    Returns:
        Random password string.

    Raises:
        ValueError: If *length* < 8.
    """
    if length < 8:
        raise ValueError(f"password length must be at least 8, got {length}")
    return "".join(secrets.choice(PASSWORD_CHARS) for _ in range(length))


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive 32-byte AES key from *password* via Argon2id.

    Args:
        password: Master vault password.
        salt: 16-byte random salt.

    Returns:
        32-byte key.
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


class Vault:
    """AES-256-GCM encrypted password vault.

    Args:
        path: Path to the vault file.
        master_password: Master password for key derivation.
    """

    def __init__(self, path: Path, master_password: str) -> None:
        if not master_password:
            raise ValueError("master_password must not be empty")
        self._path = path
        self._password = master_password
        self._salt: bytes = b""
        self._entries: list[VaultEntry] = []
        if path.exists():
            self._load()
        else:
            self._salt = secrets.token_bytes(SALT_LEN)

    def _load(self) -> None:
        raw = self._path.read_bytes()
        salt = raw[:SALT_LEN]
        nonce = raw[SALT_LEN: SALT_LEN + NONCE_LEN]
        ciphertext = raw[SALT_LEN + NONCE_LEN:]
        key = derive_key(self._password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        data = json.loads(plaintext.decode())
        self._salt = salt
        self._entries = [VaultEntry(**e) for e in data["entries"]]

    def _save(self) -> None:
        key = derive_key(self._password, self._salt)
        nonce = secrets.token_bytes(NONCE_LEN)
        aesgcm = AESGCM(key)
        data = json.dumps({"entries": [asdict(e) for e in self._entries]})
        ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
        self._path.write_bytes(self._salt + nonce + ciphertext)
        self._path.chmod(0o600)

    def add(self, site: str, username: str, password: str, notes: str = "") -> VaultEntry:
        """Add a new credential entry.

        Args:
            site: Website or service name/URL.
            username: Login username or email.
            password: Credential password.
            notes: Optional free-text notes.

        Returns:
            Created :class:`VaultEntry`.

        Raises:
            ValueError: If *site* or *username* is empty.
        """
        if not site.strip():
            raise ValueError("site must not be empty")
        if not username.strip():
            raise ValueError("username must not be empty")
        entry = VaultEntry.new(site, username, password, notes)
        self._entries.append(entry)
        self._save()
        return entry

    def get(self, entry_id: str) -> VaultEntry:
        """Get entry by ID.

        Args:
            entry_id: UUID string.

        Returns:
            :class:`VaultEntry`.

        Raises:
            KeyError: If not found.
        """
        for e in self._entries:
            if e.id == entry_id:
                return e
        raise KeyError(f"Entry not found: {entry_id}")

    def search(self, query: str) -> list[VaultEntry]:
        """Case-insensitive search by site or username.

        Args:
            query: Search string.

        Returns:
            List of matching entries.
        """
        q = query.lower()
        return [
            e for e in self._entries
            if q in e.site.lower() or q in e.username.lower()
        ]

    def list_all(self) -> list[VaultEntry]:
        """Return all entries.

        Returns:
            All vault entries.
        """
        return list(self._entries)

    def delete(self, entry_id: str) -> None:
        """Delete an entry by ID.

        Args:
            entry_id: UUID to delete.

        Raises:
            KeyError: If not found.
        """
        original = len(self._entries)
        self._entries = [e for e in self._entries if e.id != entry_id]
        if len(self._entries) == original:
            raise KeyError(f"Entry not found: {entry_id}")
        self._save()

    def update(self, entry_id: str, **kwargs: str) -> VaultEntry:
        """Update fields on an existing entry.

        Args:
            entry_id: UUID to update.
            **kwargs: Fields to update (site, username, password, notes).

        Returns:
            Updated :class:`VaultEntry`.

        Raises:
            KeyError: If not found.
        """
        entry = self.get(entry_id)
        idx = self._entries.index(entry)
        updated = VaultEntry(
            id=entry.id,
            site=kwargs.get("site", entry.site),
            username=kwargs.get("username", entry.username),
            password=kwargs.get("password", entry.password),
            notes=kwargs.get("notes", entry.notes),
            created_at=entry.created_at,
            modified_at=datetime.now(tz=UTC).isoformat(),
        )
        self._entries[idx] = updated
        self._save()
        return updated
