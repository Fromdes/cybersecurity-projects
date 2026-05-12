"""Tests for project 50 audit log core."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from project_50.core import AuditLog, Severity, make_event


class TestMakeEvent:
    def test_fields_populated(self) -> None:
        e = make_event("alice", "LOGIN", "/auth", "success", Severity.INFO)
        assert e.actor == "alice"
        assert e.action == "LOGIN"
        assert e.severity == "INFO"
        assert len(e.event_id) == 36

    def test_immutable(self) -> None:
        e = make_event("alice", "LOGIN", "/auth", "success")
        with pytest.raises((AttributeError, TypeError)):
            e.actor = "bob"  # type: ignore[misc]


class TestAuditLog:
    def _log(self, tmp_path: Path) -> AuditLog:
        return AuditLog(log_path=tmp_path / "audit.jsonl")

    def test_append_creates_file(self, tmp_path: Path) -> None:
        log = self._log(tmp_path)
        log.append("alice", "LOGIN", "/auth", "success")
        assert (tmp_path / "audit.jsonl").exists()

    def test_read_all_returns_events(self, tmp_path: Path) -> None:
        log = self._log(tmp_path)
        log.append("alice", "LOGIN", "/auth", "success")
        log.append("bob", "READ", "/files/x", "success")
        events = log.read_all()
        assert len(events) == 2

    def test_query_by_actor(self, tmp_path: Path) -> None:
        log = self._log(tmp_path)
        log.append("alice", "LOGIN", "/auth", "success")
        log.append("bob", "LOGIN", "/auth", "success")
        events = log.query(actor="alice")
        assert len(events) == 1
        assert events[0].actor == "alice"

    def test_query_by_outcome(self, tmp_path: Path) -> None:
        log = self._log(tmp_path)
        log.append("alice", "LOGIN", "/auth", "success")
        log.append("alice", "LOGIN", "/auth", "failure")
        failures = log.query(outcome="failure")
        assert len(failures) == 1

    def test_chain_intact(self, tmp_path: Path) -> None:
        log = self._log(tmp_path)
        log.append("alice", "A", "r", "success")
        log.append("bob", "B", "r", "success")
        log.append("carol", "C", "r", "failure")
        ok, msg = log.verify_chain()
        assert ok, msg

    def test_tampered_chain_detected(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log = AuditLog(log_path=log_path)
        log.append("alice", "A", "r", "success")
        log.append("bob", "B", "r", "success")
        log.append("carol", "C", "r", "success")  # third event seals the chain

        # Tamper the MIDDLE (second) event — event 3's prev_hash will no longer match
        lines = log_path.read_text().splitlines()
        data = json.loads(lines[1])
        data["actor"] = "HACKER"
        lines[1] = json.dumps(data)
        log_path.write_text("\n".join(lines) + "\n")

        ok, _ = log.verify_chain()
        assert not ok

    def test_empty_log_chain_ok(self, tmp_path: Path) -> None:
        log = self._log(tmp_path)
        ok, _ = log.verify_chain()
        assert ok

    def test_prev_hash_chained(self, tmp_path: Path) -> None:
        log = self._log(tmp_path)
        e1 = log.append("alice", "A", "r", "success")
        e2 = log.append("bob", "B", "r", "success")
        assert e2.prev_hash == e1.compute_hash()
