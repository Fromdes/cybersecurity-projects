"""Double Ratchet Algorithm — session state and encrypt/decrypt operations."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from project_97.crypto import (
    KeyPair,
    decrypt,
    dh,
    encode_public_key,
    encrypt,
    generate_dh_keypair,
    header_bytes,
    kdf_ck,
    kdf_rk,
    parse_header,
)

# ── Message model ─────────────────────────────────────────────────────────────

MAX_SKIP = 100


@dataclass(frozen=True)
class Message:
    """An encrypted Double Ratchet message."""

    header: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        """Serialize to wire bytes: 4-byte header length + header + ciphertext."""
        import struct
        return struct.pack(">I", len(self.header)) + self.header + self.ciphertext

    @staticmethod
    def from_bytes(data: bytes) -> Message:
        """Deserialize from wire bytes."""
        import struct
        hlen = struct.unpack(">I", data[:4])[0]
        header = data[4:4 + hlen]
        ciphertext = data[4 + hlen:]
        return Message(header=header, ciphertext=ciphertext)


# ── Ratchet state ─────────────────────────────────────────────────────────────

@dataclass
class RatchetState:
    """Full Double Ratchet session state for one party."""

    dhs: KeyPair
    dhr: X25519PublicKey | None
    rk: bytes
    cks: bytes | None
    ckr: bytes | None
    ns: int = 0
    nr: int = 0
    pn: int = 0
    mkskipped: dict[tuple[bytes, int], bytes] = field(default_factory=dict)


def initialize_sender(shared_secret: bytes, receiver_pub: X25519PublicKey) -> RatchetState:
    """Initialize the sender's ratchet state using shared secret and receiver's DH public key."""
    dhs = generate_dh_keypair()
    dh_out = dh(dhs[0], receiver_pub)
    rk, cks = kdf_rk(shared_secret, dh_out)
    return RatchetState(dhs=dhs, dhr=receiver_pub, rk=rk, cks=cks, ckr=None)


def initialize_receiver(shared_secret: bytes, receiver_keypair: KeyPair) -> RatchetState:
    """Initialize the receiver's ratchet state using shared secret and own DH key pair."""
    return RatchetState(
        dhs=receiver_keypair,
        dhr=None,
        rk=shared_secret,
        cks=None,
        ckr=None,
    )


def ratchet_encrypt(state: RatchetState, plaintext: bytes, ad: bytes = b"") -> Message:
    """Encrypt a message, advancing the sending chain."""
    assert state.cks is not None, "Sending chain key not initialized"
    state.cks, mk = kdf_ck(state.cks)
    hdr = header_bytes(state.dhs[1], state.pn, state.ns)
    state.ns += 1
    return Message(header=hdr, ciphertext=encrypt(mk, plaintext, ad + hdr))


def ratchet_decrypt(state: RatchetState, msg: Message, ad: bytes = b"") -> bytes:
    """Decrypt a message, performing DH or chain ratchet steps as needed."""
    dh_pub, pn, n = parse_header(msg.header)
    dh_pub_bytes = encode_public_key(dh_pub)

    # Check skipped message keys first
    skip_key = (dh_pub_bytes, n)
    if skip_key in state.mkskipped:
        mk = state.mkskipped.pop(skip_key)
        return decrypt(mk, msg.ciphertext, ad + msg.header)

    # DH ratchet step if new ratchet key
    if state.dhr is None or encode_public_key(dh_pub) != encode_public_key(state.dhr):
        _skip_message_keys(state, pn)
        _dh_ratchet(state, dh_pub)

    _skip_message_keys(state, n)
    assert state.ckr is not None
    state.ckr, mk = kdf_ck(state.ckr)
    state.nr += 1
    return decrypt(mk, msg.ciphertext, ad + msg.header)


def _skip_message_keys(state: RatchetState, until: int) -> None:
    """Pre-compute and cache skipped message keys up to *until*."""
    if state.ckr is None or until <= state.nr:
        return
    if until - state.nr > MAX_SKIP:
        raise ValueError(f"Too many skipped messages: {until - state.nr} > {MAX_SKIP}")
    while state.nr < until:
        dhr_bytes = encode_public_key(state.dhr) if state.dhr else b""
        state.ckr, mk = kdf_ck(state.ckr)
        state.mkskipped[(dhr_bytes, state.nr)] = mk
        state.nr += 1


def _dh_ratchet(state: RatchetState, dh_pub: X25519PublicKey) -> None:
    """Perform a DH ratchet step: update root key, receive chain, and send chain."""
    state.pn = state.ns
    state.ns = 0
    state.nr = 0
    state.dhr = dh_pub
    dh_out_r = dh(state.dhs[0], state.dhr)
    state.rk, state.ckr = kdf_rk(state.rk, dh_out_r)
    state.dhs = generate_dh_keypair()
    dh_out_s = dh(state.dhs[0], state.dhr)
    state.rk, state.cks = kdf_rk(state.rk, dh_out_s)


# ── High-level session ────────────────────────────────────────────────────────

@dataclass
class Session:
    """High-level messaging session wrapping a RatchetState."""

    state: RatchetState
    session_id: str

    def send(self, plaintext: str, associated_data: bytes = b"") -> bytes:
        """Encrypt and return wire bytes for a plaintext message."""
        msg = ratchet_encrypt(self.state, plaintext.encode(), associated_data)
        return msg.to_bytes()

    def receive(self, wire: bytes, associated_data: bytes = b"") -> str:
        """Decrypt wire bytes and return the plaintext string."""
        msg = Message.from_bytes(wire)
        return ratchet_decrypt(self.state, msg, associated_data).decode()


def create_session_pair(shared_secret: bytes | None = None) -> tuple[Session, Session]:
    """Create a matched (sender, receiver) session pair for testing."""
    if shared_secret is None:
        shared_secret = os.urandom(32)
    receiver_kp = generate_dh_keypair()
    sender_state = initialize_sender(shared_secret, receiver_kp[1])
    receiver_state = initialize_receiver(shared_secret, receiver_kp)
    return (
        Session(state=sender_state, session_id="alice"),
        Session(state=receiver_state, session_id="bob"),
    )
