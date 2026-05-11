# Threat Model — Project 04: Password Strength Analyzer

## Asset

User account security (protected by the evaluated password).

## STRIDE

| Threat | Rating | Notes |
|---|---|---|
| **Brute Force / Guessing** | **Critical** | Core defence — weak passwords are rated 0 |
| Information Disclosure | Low | Password never stored; `getpass` hides terminal echo |
| Spoofing | Medium | Client-side check only; always validate server-side too |
| Tampering | Low | Score output could be suppressed by malware |
| DoS | None | Offline, single-password evaluation |
| Elevation of Privilege | None | Read-only; no system calls |

## Threat Scenario

An attacker tries `password123` or a dictionary of 10M common passwords. This
tool gives the user immediate feedback that their chosen password would be cracked
in milliseconds, prompting them to choose something with higher entropy.
