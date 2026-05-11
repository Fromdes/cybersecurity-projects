# Threat Model — Project 01: Caesar & Vigenere Cipher Toolkit

## Asset

The plaintext of a message intended to be kept confidential.

## Attack Surface

This is a CLI-only, offline tool. No network access, no file system writes.

## STRIDE Analysis

| Threat | Applicable? | Notes |
|---|---|---|
| Spoofing | No | Offline tool; no identity assertions |
| Tampering | Partial | Modified ciphertext produces garbled output, not detected |
| Repudiation | No | No audit trail needed for educational tool |
| Information Disclosure | **Yes** | Caesar/Vigenere provide no real confidentiality |
| Denial of Service | No | No persistent state; trivially restarted |
| Elevation of Privilege | No | Runs with user permissions; reads no sensitive files |

## Key Finding

Classical ciphers are broken by design. A 26-key Caesar cipher has **entropy of
log₂(26) ≈ 4.7 bits** — crackable in milliseconds. Even a 6-character Vigenere
key has only 26^6 ≈ 308 million combinations, trivially exhausted with frequency
analysis in under a second.

**Recommendation:** Use AES-256-GCM (Project 08) for real confidentiality.
