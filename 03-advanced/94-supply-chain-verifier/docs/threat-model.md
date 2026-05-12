# Threat Model — Supply Chain Verifier

## STRIDE Analysis

| Threat | Component | Mitigation |
|---|---|---|
| Tampering | Release artifact | Hash verification catches modified binaries |
| Spoofing | SLSA attestation | Trusted builder allowlist prevents fake attestations |
| Repudiation | Build provenance | SLSA provenance records exact build inputs |
| Information Disclosure | Checksums file | Hashes are public by design; keys are not included |

## Supply Chain Attack Scenarios

1. **Compromised CDN/mirror**: Attacker replaces download — SHA-256 mismatch detected
2. **Fake release**: Attacker publishes artifact without trusted builder provenance
3. **Dependency confusion**: Wrong package version; SLSA subject name mismatch
4. **Builder impersonation**: Attestation claims trusted builder; trusted_builders allowlist blocks it
