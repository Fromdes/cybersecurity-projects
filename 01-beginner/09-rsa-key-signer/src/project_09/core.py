"""RSA-4096 key pair generation and PSS-SHA-256 file signing."""

from __future__ import annotations

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

RSA_KEY_SIZE: int = 4096
PUBLIC_EXPONENT: int = 65537
SIGNATURE_EXTENSION: str = ".sig"


class SignatureVerificationError(Exception):
    """Raised when a file's signature cannot be verified."""


def generate_key_pair() -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate a new RSA-4096 key pair.

    Returns:
        Tuple of (private_key, public_key).
    """
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    return private_key, private_key.public_key()


def save_private_key(key: RSAPrivateKey, path: Path, password: str) -> None:
    """Serialize *key* to a PEM file, encrypted with *password* (AES-256-CBC).

    Args:
        key: RSA private key to save.
        path: Destination path for the PEM file.
        password: Passphrase to encrypt the private key.

    Raises:
        ValueError: If *password* is empty.
    """
    if not password:
        raise ValueError("Private key password must not be empty")
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        ),
    )
    path.write_bytes(pem)


def save_public_key(key: RSAPublicKey, path: Path) -> None:
    """Serialize *key* to an unencrypted PEM file.

    Args:
        key: RSA public key to save.
        path: Destination path for the PEM file.
    """
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def load_private_key(path: Path, password: str) -> RSAPrivateKey:
    """Load an RSA private key from a PEM file.

    Args:
        path: Path to the PEM-encoded private key.
        password: Decryption passphrase.

    Returns:
        Decrypted RSA private key.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError: If the password is wrong or the file is corrupt.
    """
    if not path.exists():
        raise FileNotFoundError(f"Private key file not found: {path}")
    raw = path.read_bytes()
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    try:
        key = load_pem_private_key(raw, password=password.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Failed to load private key from {path}: {exc}") from exc
    if not isinstance(key, RSAPrivateKey):
        raise ValueError(f"Key in {path} is not an RSA private key")
    return key


def load_public_key(path: Path) -> RSAPublicKey:
    """Load an RSA public key from a PEM file.

    Args:
        path: Path to the PEM-encoded public key.

    Returns:
        RSA public key.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError: If the file is not a valid public key.
    """
    if not path.exists():
        raise FileNotFoundError(f"Public key file not found: {path}")
    raw = path.read_bytes()
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    try:
        key = load_pem_public_key(raw)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Failed to load public key from {path}: {exc}") from exc
    if not isinstance(key, RSAPublicKey):
        raise ValueError(f"Key in {path} is not an RSA public key")
    return key


def sign_file(path: Path, private_key: RSAPrivateKey) -> bytes:
    """Compute an RSA-PSS/SHA-256 signature over the contents of *path*.

    Args:
        path: File to sign.
        private_key: RSA private key.

    Returns:
        Raw signature bytes.

    Raises:
        FileNotFoundError: If *path* does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(f"File to sign not found: {path}")
    data = path.read_bytes()
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_file(path: Path, signature: bytes, public_key: RSAPublicKey) -> bool:
    """Verify an RSA-PSS/SHA-256 signature against *path*.

    Args:
        path: File whose content to verify.
        signature: Previously computed signature bytes.
        public_key: RSA public key matching the signing key.

    Returns:
        ``True`` if the signature is valid.

    Raises:
        FileNotFoundError: If *path* does not exist.
        SignatureVerificationError: If the signature is invalid.
    """
    if not path.exists():
        raise FileNotFoundError(f"File to verify not found: {path}")
    data = path.read_bytes()
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature as exc:
        raise SignatureVerificationError(
            "Signature verification failed — file may have been modified."
        ) from exc
