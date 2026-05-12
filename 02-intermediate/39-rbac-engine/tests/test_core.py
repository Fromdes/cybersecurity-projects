"""Tests for RBAC Engine core logic."""

from __future__ import annotations

import pytest

from project_39.core import Permission, RBACEngine

SAMPLE_YAML = """
roles:
  viewer:
    permissions:
      - reports:read
      - dashboard:view
    parents: []
  editor:
    permissions:
      - reports:write
    parents:
      - viewer
  admin:
    permissions:
      - "*:*"
    parents:
      - editor
users:
  alice:
    roles:
      - admin
  bob:
    roles:
      - editor
  carol:
    roles:
      - viewer
  nobody:
    roles: []
"""


@pytest.fixture()
def engine() -> RBACEngine:
    return RBACEngine.from_yaml(SAMPLE_YAML)


class TestPermission:
    def test_exact_match(self) -> None:
        p = Permission("reports", "read")
        assert p.matches("reports", "read")

    def test_no_match(self) -> None:
        p = Permission("reports", "read")
        assert not p.matches("reports", "write")

    def test_wildcard_action(self) -> None:
        p = Permission("reports", "*")
        assert p.matches("reports", "read")
        assert p.matches("reports", "delete")

    def test_wildcard_resource(self) -> None:
        p = Permission("*", "read")
        assert p.matches("anything", "read")

    def test_full_wildcard(self) -> None:
        p = Permission("*", "*")
        assert p.matches("foo", "bar")

    def test_str_representation(self) -> None:
        assert str(Permission("a", "b")) == "a:b"


class TestRBACEngine:
    def test_load_from_yaml(self, engine: RBACEngine) -> None:
        assert engine.get_role("admin") is not None
        assert engine.get_user("alice") is not None

    def test_viewer_can_read(self, engine: RBACEngine) -> None:
        decision = engine.check("carol", "reports", "read")
        assert decision.allowed

    def test_viewer_cannot_write(self, engine: RBACEngine) -> None:
        decision = engine.check("carol", "reports", "write")
        assert not decision.allowed

    def test_editor_inherits_viewer_permissions(self, engine: RBACEngine) -> None:
        decision = engine.check("bob", "dashboard", "view")
        assert decision.allowed

    def test_admin_wildcard(self, engine: RBACEngine) -> None:
        decision = engine.check("alice", "anything", "anAction")
        assert decision.allowed

    def test_no_roles_denied(self, engine: RBACEngine) -> None:
        decision = engine.check("nobody", "reports", "read")
        assert not decision.allowed

    def test_unknown_user_denied(self, engine: RBACEngine) -> None:
        decision = engine.check("ghost", "reports", "read")
        assert not decision.allowed

    def test_decision_metadata(self, engine: RBACEngine) -> None:
        decision = engine.check("carol", "reports", "read")
        assert decision.matched_role is not None
        assert decision.matched_permission is not None

    def test_list_user_permissions(self, engine: RBACEngine) -> None:
        perms = engine.list_user_permissions("bob")
        assert "reports:read" in perms
        assert "reports:write" in perms
        assert "dashboard:view" in perms

    def test_list_permissions_unknown_user(self, engine: RBACEngine) -> None:
        with pytest.raises(KeyError):
            engine.list_user_permissions("unknown")

    def test_role_cycle_safety(self) -> None:
        e = RBACEngine()
        r1 = e.add_role("r1", parents=["r2"])
        r2 = e.add_role("r2", parents=["r1"])
        r1.add_permission("res", "act")
        u = e.add_user("u1")
        u.assign_role("r1")
        decision = e.check("u1", "res", "act")
        assert decision.allowed

    def test_grant_and_revoke(self) -> None:
        e = RBACEngine()
        e.add_role("r")
        e.grant_permission("r", "files", "delete")
        u = e.add_user("u1")
        e.assign_role("u1", "r")
        assert e.check("u1", "files", "delete").allowed
        e.revoke_role("u1", "r")
        assert not e.check("u1", "files", "delete").allowed

    def test_serialization_roundtrip(self, engine: RBACEngine) -> None:
        data = engine.to_dict()
        restored = RBACEngine.from_dict(data)
        assert restored.check("alice", "anything", "anAction").allowed
        assert not restored.check("carol", "reports", "write").allowed

    def test_unknown_role_raises(self, engine: RBACEngine) -> None:
        with pytest.raises(KeyError):
            engine.get_role("nonexistent")

    def test_assign_nonexistent_role_raises(self, engine: RBACEngine) -> None:
        with pytest.raises(KeyError):
            engine.assign_role("alice", "nonexistent_role")
