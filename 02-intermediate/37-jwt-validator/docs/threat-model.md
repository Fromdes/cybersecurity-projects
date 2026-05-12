# Threat Model — JWT Validator & Inspector

## STRIDE Table

| Threat | Example | Control |
|--------|---------|---------|
| Spoofing | Forged JWT with `alg:none` | Reject `none` before PyJWT |
| Tampering | Modified payload, valid signature skipped | Signature verification mandatory |
| Repudiation | No audit trail for token use | SHA-256 fingerprint logged |
| Info Disclosure | Sensitive claims in logs | Only `sub` and fingerprint prefix logged |
| Elevation of Privilege | HS/RS confusion attack | Explicit algorithm allowlist |
| DoS | Very long token input | PyJWT handles gracefully; no unbounded parse |

## MITRE ATT&CK Coverage

- T1606 — Forge Web Credentials: validated signature prevents forged JWTs
- T1550.001 — Use Alternate Auth Material: `exp` and age checks limit token replay
- T1078 — Valid Accounts: issuer/audience binding narrows token scope
