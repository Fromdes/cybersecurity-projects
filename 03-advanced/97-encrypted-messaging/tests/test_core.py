"""Tests for project_97 core — Double Ratchet Encrypted Messaging."""

from __future__ import annotations

import os

import pytest

from project_97.core import (
    Message,
    create_session_pair,
)


class TestSessionPair:
    def test_basic_encrypt_decrypt(self) -> None:
        alice, bob = create_session_pair()
        wire = alice.send("hello")
        assert bob.receive(wire) == "hello"

    def test_multiple_messages_alice_to_bob(self) -> None:
        alice, bob = create_session_pair()
        msgs = [f"msg {i}" for i in range(10)]
        for m in msgs:
            wire = alice.send(m)
            assert bob.receive(wire) == m

    def test_bidirectional_exchange(self) -> None:
        alice, bob = create_session_pair()
        wire1 = alice.send("hi from alice")
        assert bob.receive(wire1) == "hi from alice"
        wire2 = bob.send("hi from bob")
        assert alice.receive(wire2) == "hi from bob"

    def test_dh_ratchet_happens_on_direction_change(self) -> None:
        alice, bob = create_session_pair()
        # Alice sends, then Bob replies — triggers DH ratchet
        assert bob.receive(alice.send("a1")) == "a1"
        assert bob.receive(alice.send("a2")) == "a2"
        assert alice.receive(bob.send("b1")) == "b1"
        assert bob.receive(alice.send("a3")) == "a3"  # new ratchet

    def test_replay_rejected(self) -> None:
        alice, bob = create_session_pair()
        wire = alice.send("secret")
        bob.receive(wire)
        with pytest.raises(Exception):
            bob.receive(wire)

    def test_tampered_ciphertext_rejected(self) -> None:
        alice, bob = create_session_pair()
        wire = alice.send("hello")
        # Flip a byte in the ciphertext portion
        wire_bytes = bytearray(wire)
        wire_bytes[-1] ^= 0xFF
        with pytest.raises(Exception):
            bob.receive(bytes(wire_bytes))

    def test_out_of_order_delivery(self) -> None:
        alice, bob = create_session_pair()
        w1 = alice.send("first")
        w2 = alice.send("second")
        w3 = alice.send("third")
        # Deliver out of order
        assert bob.receive(w2) == "second"
        assert bob.receive(w3) == "third"
        assert bob.receive(w1) == "first"

    def test_associated_data_mismatch_rejected(self) -> None:
        alice, bob = create_session_pair()
        wire = alice.send("hello", associated_data=b"session-1")
        with pytest.raises(Exception):
            bob.receive(wire, associated_data=b"session-2")

    def test_associated_data_matches(self) -> None:
        alice, bob = create_session_pair()
        wire = alice.send("hello", associated_data=b"same-ad")
        assert bob.receive(wire, associated_data=b"same-ad") == "hello"

    def test_unicode_message(self) -> None:
        alice, bob = create_session_pair()
        msg = "Merhaba dünya! 🔐"
        assert bob.receive(alice.send(msg)) == msg

    def test_empty_message(self) -> None:
        alice, bob = create_session_pair()
        assert bob.receive(alice.send("")) == ""

    def test_long_message(self) -> None:
        alice, bob = create_session_pair()
        long_msg = "x" * 10000
        assert bob.receive(alice.send(long_msg)) == long_msg


class TestMessageSerialization:
    def test_roundtrip(self) -> None:
        alice, _ = create_session_pair()
        wire = alice.send("test")
        msg = Message.from_bytes(wire)
        assert len(msg.header) == 40  # 32 DH + 4 pn + 4 n
        assert len(msg.ciphertext) > 0
        assert msg.to_bytes() == wire


class TestCrypto:
    def test_shared_secret_determinism(self) -> None:
        secret = os.urandom(32)
        alice, bob = create_session_pair(shared_secret=secret)
        wire = alice.send("ping")
        assert bob.receive(wire) == "ping"

    def test_different_sessions_incompatible(self) -> None:
        alice1, bob1 = create_session_pair()
        alice2, bob2 = create_session_pair()
        wire = alice1.send("hello")
        with pytest.raises(Exception):
            bob2.receive(wire)
