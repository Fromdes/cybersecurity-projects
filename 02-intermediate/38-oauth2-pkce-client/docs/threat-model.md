# Threat Model — OAuth2 PKCE Client

## STRIDE Table

| Threat | Example | Control |
|--------|---------|---------|
| Spoofing | Stolen authorization code used by attacker | code_verifier proof required at token exchange |
| Tampering | MITM intercepts code in redirect | S256 challenge cannot be reversed |
| Repudiation | No link between code and original requester | Verifier ties request to token exchange |
| Info Disclosure | Verifier logged accidentally | describe_pkce() omits verifier |
| Elevation of Privilege | CSRF: attacker injects their code | state parameter verified with compare_digest |
| DoS | Repeated token exchange attempts | Token endpoint handles; no local loop |

## MITRE ATT&CK Coverage

- T1528 — Steal Application Access Token: PKCE prevents code interception attacks
- T1550.001 — App Access Token Abuse: short-lived tokens with PKCE binding
- T1078 — Valid Accounts: state CSRF check prevents session fixation
