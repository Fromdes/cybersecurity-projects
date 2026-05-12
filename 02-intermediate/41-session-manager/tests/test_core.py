"""Tests for Session Manager core logic."""

from __future__ import annotations

import time

import pytest

from project_41.core import (
    MAX_SESSIONS_PER_USER,
    SessionStatus,
    SessionStore,
)


@pytest.fixture()
def store() -> SessionStore:
    return SessionStore(ttl=60, idle_timeout=30)


class TestCreateSession:
    def test_creates_with_unique_ids(self, store: SessionStore) -> None:
        s1 = store.create("u1")
        s2 = store.create("u1")
        assert s1.session_id != s2.session_id

    def test_csrf_tokens_are_unique(self, store: SessionStore) -> None:
        s1 = store.create("u1")
        s2 = store.create("u1")
        assert s1.csrf_token != s2.csrf_token

    def test_metadata_stored(self, store: SessionStore) -> None:
        s = store.create("u1", metadata={"role": "admin"})
        assert s.metadata["role"] == "admin"

    def test_ip_and_ua_stored(self, store: SessionStore) -> None:
        s = store.create("u1", ip_address="10.0.0.1", user_agent="TestAgent/1")
        assert s.ip_address == "10.0.0.1"
        assert s.user_agent == "TestAgent/1"

    def test_session_cap_enforced(self) -> None:
        store = SessionStore(ttl=60, idle_timeout=30, max_per_user=2)
        s1 = store.create("u1")
        s2 = store.create("u1")
        store.create("u1")  # cap=2, s1 should be revoked
        assert store._sessions[s1.session_id].status == SessionStatus.REVOKED
        assert store._sessions[s2.session_id].status == SessionStatus.ACTIVE


class TestValidateSession:
    def test_valid_session(self, store: SessionStore) -> None:
        s = store.create("u1")
        result = store.validate(s.session_id)
        assert result.valid
        assert result.reason == "ok"

    def test_unknown_session(self, store: SessionStore) -> None:
        result = store.validate("nonexistent-token")
        assert not result.valid
        assert result.reason == "not_found"

    def test_expired_session(self) -> None:
        store = SessionStore(ttl=1, idle_timeout=60)
        s = store.create("u1")
        time.sleep(1.1)
        result = store.validate(s.session_id)
        assert not result.valid
        assert result.reason == "expired"

    def test_idle_timeout(self) -> None:
        store = SessionStore(ttl=60, idle_timeout=1)
        s = store.create("u1")
        time.sleep(1.1)
        result = store.validate(s.session_id)
        assert not result.valid
        assert result.reason == "idle_timeout"

    def test_revoked_session(self, store: SessionStore) -> None:
        s = store.create("u1")
        store.revoke(s.session_id)
        result = store.validate(s.session_id)
        assert not result.valid
        assert result.reason == "revoked"

    def test_last_accessed_updated(self, store: SessionStore) -> None:
        s = store.create("u1")
        original_la = s.last_accessed
        time.sleep(0.05)
        store.validate(s.session_id)
        assert s.last_accessed > original_la


class TestRotateSession:
    def test_rotation_returns_new_session(self, store: SessionStore) -> None:
        s = store.create("u1")
        new_s = store.rotate(s.session_id)
        assert new_s.session_id != s.session_id
        assert new_s.user_id == s.user_id
        assert new_s.csrf_token != s.csrf_token

    def test_old_token_marked_rotated(self, store: SessionStore) -> None:
        s = store.create("u1")
        store.rotate(s.session_id)
        assert store._sessions[s.session_id].status == SessionStatus.ROTATED

    def test_old_token_valid_during_grace(self, store: SessionStore) -> None:
        s = store.create("u1")
        store.rotate(s.session_id)
        result = store.validate(s.session_id)
        assert result.valid  # within grace period

    def test_cannot_rotate_revoked(self, store: SessionStore) -> None:
        s = store.create("u1")
        store.revoke(s.session_id)
        with pytest.raises(ValueError):
            store.rotate(s.session_id)


class TestRevokeSession:
    def test_revoke_single(self, store: SessionStore) -> None:
        s = store.create("u1")
        assert store.revoke(s.session_id)
        assert store._sessions[s.session_id].status == SessionStatus.REVOKED

    def test_revoke_nonexistent(self, store: SessionStore) -> None:
        assert not store.revoke("bad-id")

    def test_revoke_all(self, store: SessionStore) -> None:
        store.create("u1")
        store.create("u1")
        n = store.revoke_all("u1")
        assert n == 2
        remaining = store.list_user_sessions("u1")
        assert all(s.status == SessionStatus.REVOKED for s in remaining)

    def test_revoke_all_other_users_untouched(self, store: SessionStore) -> None:
        store.create("u1")
        s2 = store.create("u2")
        store.revoke_all("u1")
        assert store._sessions[s2.session_id].status == SessionStatus.ACTIVE


class TestCSRF:
    def test_valid_csrf(self, store: SessionStore) -> None:
        s = store.create("u1")
        assert store.verify_csrf(s.session_id, s.csrf_token)

    def test_invalid_csrf(self, store: SessionStore) -> None:
        s = store.create("u1")
        assert not store.verify_csrf(s.session_id, "wrong-token")

    def test_csrf_fails_on_invalid_session(self, store: SessionStore) -> None:
        assert not store.verify_csrf("bad-session", "any-token")


class TestPurge:
    def test_purge_removes_revoked(self, store: SessionStore) -> None:
        s = store.create("u1")
        store.revoke(s.session_id)
        n = store.purge_expired()
        assert n == 1
        assert s.session_id not in store._sessions
