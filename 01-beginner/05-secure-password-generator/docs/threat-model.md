# Threat Model — Project 05: Secure Password Generator

## STRIDE

| Threat | Rating | Notes |
|---|---|---|
| **Brute Force Prevention** | **Core feature** | High entropy defeats offline cracking |
| Information Disclosure | Low | Generated password not stored; pass directly to target |
| Tampering | Low | If this binary is replaced, all generated passwords are compromised |
| DoS | None | CPU-bound; no network, no shared state |
| Elevation of Privilege | None | Read-only; no system access |

## Supply Chain Note

If an attacker replaces this tool on your system, every password generated is known
to them. Verify the tool binary hash (Project 02) and sign it (Project 09).
