# Architecture — RBAC Engine

## Components

```
cli.py    Click CLI (check / list-permissions / dump / init-policy)
core.py   Permission, Role, User, Decision dataclasses; RBACEngine class
```

## Data Model

```
Role ──── permissions: set[Permission(resource, action)]
     ──── parents: list[str]  (role inheritance)

User ──── roles: set[str]

RBACEngine ──── _roles: dict[name → Role]
           ──── _users: dict[user_id → User]
```

## Authorization Flow

```
check(user_id, resource, action)
  1. Lookup user → if missing → DENY
  2. For each assigned role:
       _effective_permissions(role) — recursive DFS with cycle guard
       For each (role_name, Permission):
           if permission.matches(resource, action) → ALLOW + metadata
  3. If no match found → DENY
```

## Policy Format (YAML)

```yaml
roles:
  viewer:
    permissions: ["reports:read"]
    parents: []
  editor:
    permissions: ["reports:write"]
    parents: ["viewer"]

users:
  alice:
    roles: ["editor"]
```
