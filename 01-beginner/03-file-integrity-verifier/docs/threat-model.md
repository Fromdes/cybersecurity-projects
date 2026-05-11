# Threat Model — Project 03: File Integrity Verifier

## Asset

Integrity of monitored files (configs, binaries, web content).

## STRIDE

| Threat | Rating | Mitigation |
|---|---|---|
| Spoofing | Low | N/A for offline file monitoring |
| **Tampering** | **Critical** | SHA-256 hash detects any bit-level modification |
| Repudiation | High | Sign baseline with RSA (Project 09); store on WORM media |
| Information Disclosure | Medium | Baseline reveals file names; store in restricted directory |
| DoS | Low | Hashing many large files is slow but not a security risk |
| Elevation of Privilege | Low | Tool is read-only; no execution of monitored files |

## Attack Scenarios

1. **Attacker modifies /etc/passwd** → SHA-256 mismatch detected at next check run
2. **Attacker also updates baseline** → Mitigated by storing baseline on read-only media
3. **Attacker deletes a cron job** → Deletion detected by missing key in current scan
