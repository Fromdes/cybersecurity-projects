# Architecture Overview

This document describes the design philosophy and common architectural patterns used across all 100 projects.

---

## Design Philosophy

Every project answers one question first: **"Which attack does this defend against?"**

From there, the architecture flows:

1. **Threat** — Identify the MITRE ATT&CK technique
2. **Detection/Prevention** — Design the defensive mechanism
3. **Implementation** — Write the Python tool
4. **Validation** — Test against known-bad inputs/behaviors

---

## Common Module Structure

All projects follow this layout:

```
src/project_NN/
├── __init__.py      # Public API exports + version
├── __main__.py      # Entry point: python -m src.project_NN
├── cli.py           # argparse/click interface — thin, delegates to core
└── core.py          # Business logic — pure functions, no I/O side effects
```

**Key rule**: `cli.py` handles I/O; `core.py` is pure logic. This makes unit testing trivial.

---

## Data Flow Pattern

```
stdin / file / network
        ↓
   [cli.py] — validates & parses input (pydantic models)
        ↓
   [core.py] — processes data, raises typed exceptions
        ↓
   [cli.py] — formats output, handles errors, exits with code
        ↓
stdout / file / log
```

---

## Configuration

- Configuration: YAML or TOML files, validated by `pydantic`
- Secrets: environment variables or `.env` files (never in code)
- Logging: `stdlib logging` with `StructuredFormatter` — JSON output in production, human-readable in dev

---

## Testing Strategy

| Layer | Tool | What it tests |
|-------|------|---------------|
| Unit | `pytest` | `core.py` functions with known inputs |
| CLI | `pytest` + `click.testing.CliRunner` | Argument parsing, output format |
| Integration | `pytest -m integration` | Real file I/O, network (marked, skipped in CI if needed) |
| Security | `bandit` | AST-based security issue detection |
| Types | `mypy --strict` | Full type coverage |

---

## Levels and Progression

### Level 1 — Beginner (01-35)
- **Focus**: Core concepts (crypto, hashing, encoding), simple CLI tools
- **Dependencies**: Standard library + `cryptography`, `requests`, `psutil`
- **Architecture**: Single `core.py` + `cli.py`, no external services

### Level 2 — Intermediate (36-75)
- **Focus**: Detection engines, auth frameworks, threat intel, network monitoring
- **Dependencies**: `scapy`, `pyjwt`, `yara-python`, `stix2`, `scikit-learn`
- **Architecture**: May include daemon mode, Redis for state, Flask for web UI

### Level 3 — Advanced (76-100)
- **Focus**: SIEM, EDR, forensics, cloud security, ML anomaly detection
- **Dependencies**: Full stack including `volatility3`, `boto3`, `fastapi`, `pandas`
- **Architecture**: Multi-component systems; some use async I/O or worker processes

---

## Security Hardening (applied everywhere)

- All external input validated via `pydantic` before processing
- File paths resolved and checked against allowed directories (no path traversal)
- Subprocess calls use argument lists, never shell=True
- Cryptographic operations use `cryptography` library (not `hashlib` for passwords)
- Secrets loaded from environment, logged nowhere
- Error messages never include internal paths, stack traces, or secret values in production output
