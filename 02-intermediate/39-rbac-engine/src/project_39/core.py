"""RBAC Engine — Role-Based Access Control with role hierarchy and audit log.

Defends against: T1078 (Valid Accounts), T1548 (Abuse Elevation Control Mechanism),
T1134 (Access Token Manipulation).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import yaml

logger = logging.getLogger(__name__)

WILDCARD: str = "*"


@dataclass(frozen=True)
class Permission:
    """A single resource:action permission."""

    resource: str
    action: str

    def __str__(self) -> str:
        return f"{self.resource}:{self.action}"

    def matches(self, resource: str, action: str) -> bool:
        """Check if this permission covers the given resource and action."""
        res_ok = self.resource == WILDCARD or self.resource == resource
        act_ok = self.action == WILDCARD or self.action == action
        return res_ok and act_ok


@dataclass
class Role:
    """A named role with a set of permissions and optional parent roles."""

    name: str
    permissions: set[Permission] = field(default_factory=set)
    parents: list[str] = field(default_factory=list)

    def add_permission(self, resource: str, action: str) -> None:
        """Add a permission to this role.

        Args:
            resource: Resource name or '*'.
            action: Action name or '*'.
        """
        self.permissions.add(Permission(resource=resource, action=action))


@dataclass
class User:
    """A user with an assigned set of role names."""

    user_id: str
    roles: set[str] = field(default_factory=set)

    def assign_role(self, role_name: str) -> None:
        """Assign a role to this user.

        Args:
            role_name: Name of the role to assign.
        """
        self.roles.add(role_name)

    def revoke_role(self, role_name: str) -> None:
        """Revoke a role from this user.

        Args:
            role_name: Name of the role to revoke.
        """
        self.roles.discard(role_name)


@dataclass(frozen=True)
class Decision:
    """Result of an authorization check."""

    allowed: bool
    user_id: str
    resource: str
    action: str
    matched_role: str | None
    matched_permission: str | None

    def __str__(self) -> str:
        verdict = "ALLOW" if self.allowed else "DENY"
        return (
            f"[{verdict}] user={self.user_id} "
            f"resource={self.resource} action={self.action} "
            f"role={self.matched_role} perm={self.matched_permission}"
        )


class RBACEngine:
    """Role-Based Access Control engine with role hierarchy."""

    def __init__(self) -> None:
        self._roles: dict[str, Role] = {}
        self._users: dict[str, User] = {}

    def add_role(self, name: str, parents: list[str] | None = None) -> Role:
        """Create and register a role.

        Args:
            name: Unique role name.
            parents: Optional parent role names for inheritance.

        Returns:
            The newly created Role.
        """
        role = Role(name=name, parents=parents or [])
        self._roles[name] = role
        logger.debug("Role added name=%s parents=%s", name, parents)
        return role

    def get_role(self, name: str) -> Role:
        """Retrieve a role by name.

        Args:
            name: Role name.

        Returns:
            Role object.

        Raises:
            KeyError: If role not found.
        """
        if name not in self._roles:
            raise KeyError(f"Role '{name}' not found")
        return self._roles[name]

    def grant_permission(self, role_name: str, resource: str, action: str) -> None:
        """Grant a permission to a role.

        Args:
            role_name: Target role name.
            resource: Resource name or '*'.
            action: Action name or '*'.
        """
        self.get_role(role_name).add_permission(resource, action)

    def add_user(self, user_id: str) -> User:
        """Create and register a user.

        Args:
            user_id: Unique user identifier.

        Returns:
            The newly created User.
        """
        user = User(user_id=user_id)
        self._users[user_id] = user
        logger.debug("User added user_id=%s", user_id)
        return user

    def get_user(self, user_id: str) -> User:
        """Retrieve a user by ID.

        Args:
            user_id: User identifier.

        Returns:
            User object.

        Raises:
            KeyError: If user not found.
        """
        if user_id not in self._users:
            raise KeyError(f"User '{user_id}' not found")
        return self._users[user_id]

    def assign_role(self, user_id: str, role_name: str) -> None:
        """Assign a role to a user.

        Args:
            user_id: User identifier.
            role_name: Role to assign (must exist).
        """
        self.get_role(role_name)  # validate existence
        self.get_user(user_id).assign_role(role_name)
        logger.info("Role assigned user_id=%s role=%s", user_id, role_name)

    def revoke_role(self, user_id: str, role_name: str) -> None:
        """Revoke a role from a user.

        Args:
            user_id: User identifier.
            role_name: Role to revoke.
        """
        self.get_user(user_id).revoke_role(role_name)
        logger.info("Role revoked user_id=%s role=%s", user_id, role_name)

    def _effective_permissions(self, role_name: str, visited: set[str] | None = None) -> list[tuple[str, Permission]]:
        """Recursively collect permissions including inherited ones.

        Args:
            role_name: Starting role name.
            visited: Already-visited role names (cycle guard).

        Returns:
            List of (role_name, Permission) tuples.
        """
        if visited is None:
            visited = set()
        if role_name in visited:
            return []
        visited.add(role_name)

        role = self._roles.get(role_name)
        if role is None:
            return []

        result: list[tuple[str, Permission]] = [(role_name, p) for p in role.permissions]
        for parent in role.parents:
            result.extend(self._effective_permissions(parent, visited))
        return result

    def check(self, user_id: str, resource: str, action: str) -> Decision:
        """Check whether a user is authorized for resource:action.

        Args:
            user_id: User identifier.
            resource: Resource being accessed.
            action: Action being performed.

        Returns:
            Decision with allow/deny verdict and audit metadata.
        """
        user = self._users.get(user_id)
        if user is None:
            logger.warning("AuthZ DENY unknown user user_id=%s", user_id)
            return Decision(
                allowed=False,
                user_id=user_id,
                resource=resource,
                action=action,
                matched_role=None,
                matched_permission=None,
            )

        for role_name in user.roles:
            for owning_role, perm in self._effective_permissions(role_name):
                if perm.matches(resource, action):
                    decision = Decision(
                        allowed=True,
                        user_id=user_id,
                        resource=resource,
                        action=action,
                        matched_role=owning_role,
                        matched_permission=str(perm),
                    )
                    logger.info("AuthZ %s", decision)
                    return decision

        decision = Decision(
            allowed=False,
            user_id=user_id,
            resource=resource,
            action=action,
            matched_role=None,
            matched_permission=None,
        )
        logger.warning("AuthZ %s", decision)
        return decision

    def list_user_permissions(self, user_id: str) -> list[str]:
        """Return all effective permission strings for a user.

        Args:
            user_id: User identifier.

        Returns:
            Sorted list of 'resource:action' strings.
        """
        user = self.get_user(user_id)
        perms: set[str] = set()
        for role_name in user.roles:
            for _, perm in self._effective_permissions(role_name):
                perms.add(str(perm))
        return sorted(perms)

    def to_dict(self) -> dict[str, Any]:
        """Serialize engine state to a plain dict.

        Returns:
            Dict suitable for YAML/JSON serialization.
        """
        return {
            "roles": {
                name: {
                    "permissions": [str(p) for p in role.permissions],
                    "parents": role.parents,
                }
                for name, role in self._roles.items()
            },
            "users": {
                uid: {"roles": sorted(u.roles)}
                for uid, u in self._users.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RBACEngine:
        """Load engine from a plain dict (inverse of to_dict).

        Args:
            data: Dict with 'roles' and 'users' keys.

        Returns:
            Populated RBACEngine instance.
        """
        engine = cls()
        for name, rdata in data.get("roles", {}).items():
            role = engine.add_role(name, parents=rdata.get("parents", []))
            for perm_str in rdata.get("permissions", []):
                parts = perm_str.split(":", 1)
                if len(parts) == 2:
                    role.add_permission(parts[0], parts[1])
        for uid, udata in data.get("users", {}).items():
            user = engine.add_user(uid)
            for role_name in udata.get("roles", []):
                if role_name in engine._roles:
                    user.assign_role(role_name)
        return engine

    @classmethod
    def from_yaml(cls, yaml_text: str) -> RBACEngine:
        """Load engine from YAML text.

        Args:
            yaml_text: YAML-formatted policy string.

        Returns:
            Populated RBACEngine instance.
        """
        data: dict[str, Any] = yaml.safe_load(yaml_text)
        return cls.from_dict(data)
