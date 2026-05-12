# Threat Model — WebAuthn/FIDO2 Verifier

## STRIDE Table

| Threat | Example | Control |
|--------|---------|---------|
| Spoofing | Replayed authentication response | Single-use challenge; sign counter |
| Tampering | Modified authenticator data | RP ID hash verified (constant-time) |
| Repudiation | Deny authentication occurred | Sign counter stored server-side |
| Info Disclosure | Challenge reuse leaks user activity | Challenges consumed on first use |
| Elevation of Privilege | Cross-origin token theft | Origin binding in clientDataJSON |
| DoS | Challenge flooding | Challenges expire out of scope; set-based store |

## MITRE ATT&CK Coverage

- T1078 — Valid Accounts: phishing-resistant authentication (no shared secret)
- T1556 — Modify Authentication Process: RP ID + origin binding defeats MITM
- T1110 — Brute Force: public-key based; no password to brute-force
