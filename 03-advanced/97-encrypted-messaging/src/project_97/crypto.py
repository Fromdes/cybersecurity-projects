"""Cryptographic primitives for the Double Ratchet implementation."""

from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ── Key types ─────────────────────────────────────────────────────────────────

KeyPair = tuple[X25519PrivateKey, X25519PublicKey]

KDF_INFO_RK = b"double-ratchet-root-key"
KDF_INFO_CK = b"double-ratchet-chain-key"
HKDF_SALT = b"\x00" * 32


def generate_dh_keypair() -> KeyPair:
    """Generate a new X25519 key pair."""
    private = X25519PrivateKey.generate()
    return private, private.public_key()


def dh(private: X25519PrivateKey, public: X25519PublicKey) -> bytes:
    """Perform a DH exchange and return the shared secret bytes."""
    return private.exchange(public)


def kdf_rk(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    """Derive new root key and chain key from root key + DH output using HKDF."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=root_key, info=KDF_INFO_RK)
    out = hkdf.derive(dh_output)
    return out[:32], out[32:]


def kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    """Derive new chain key and message key from current chain key using HMAC."""
    h1 = hmac.HMAC(chain_key, hashes.SHA256())
    h1.update(b"\x01")
    msg_key = h1.finalize()

    h2 = hmac.HMAC(chain_key, hashes.SHA256())
    h2.update(b"\x02")
    new_ck = h2.finalize()

    return new_ck, msg_key


def encrypt(msg_key: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    """Encrypt plaintext using AES-256-GCM with the given message key."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(msg_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt(msg_key: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    """Decrypt ciphertext using AES-256-GCM with the given message key."""
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    aesgcm = AESGCM(msg_key)
    return aesgcm.decrypt(nonce, ct, associated_data)


def encode_public_key(pub: X25519PublicKey) -> bytes:
    """Serialize an X25519 public key to raw bytes."""
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def decode_public_key(raw: bytes) -> X25519PublicKey:
    """Deserialize an X25519 public key from raw bytes."""
    return X25519PublicKey.from_public_bytes(raw)


def header_bytes(dh_pub: X25519PublicKey, pn: int, n: int) -> bytes:
    """Encode a message header: DH public key (32 bytes) + pn (4) + n (4)."""
    return encode_public_key(dh_pub) + struct.pack(">II", pn, n)


def parse_header(data: bytes) -> tuple[X25519PublicKey, int, int]:
    """Parse a message header into (DH public key, pn, n)."""
    dh_pub = decode_public_key(data[:32])
    pn, n = struct.unpack(">II", data[32:40])
    return dh_pub, pn, n
