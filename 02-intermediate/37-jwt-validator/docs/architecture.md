# Architecture — JWT Validator & Inspector

## Components

```
cli.py          Click CLI (inspect / validate commands)
core.py         Decode, inspect, and validate logic; ValidationResult dataclass
```

## Data Flow

```
Raw JWT string
    │
    ▼
decode_header_unsafe() ──► JWTHeader
decode_payload_unsafe() ──► JWTClaims
    │
    ▼ (validate command only)
jwt.decode() with allowed algorithms
    │
    ▼
ValidationResult (status, warnings, errors, fingerprint)
```

## Security Decisions

- Algorithm `none` is always rejected before PyJWT even runs.
- Symmetric algorithms (HS*) produce a warning; RS*/ES*/PS* preferred.
- Hard cap of 24 h on token age regardless of `exp`.
- Token fingerprinted with SHA-256 for audit logs.
