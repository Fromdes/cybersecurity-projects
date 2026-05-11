# Architecture — Project 09: RSA Key Pair Generator & File Signer

## Why PSS Padding?

PKCS#1 v1.5 padding is deterministic and has known theoretical weaknesses
(Bleichenbacher attack variants). RSA-PSS is probabilistic (random salt per
signature) and is provably secure in the random oracle model. FIPS 186-5 now
mandates PSS for new applications.

## Signing Large Files with Prehashed

Rather than loading the entire file into memory for signing, we:
1. Compute SHA-256(file) using streaming (1 MiB chunks)
2. Call `private_key.sign(digest, PSS(...), Prehashed(SHA256()))`

This allows signing files larger than available RAM.

## Key Storage

Private keys are stored as PKCS#8 PEM, encrypted with `BestAvailableEncryption`
(currently AES-256-CBC + PBKDF2-SHA512). Public keys use SubjectPublicKeyInfo
PEM — the standard format expected by OpenSSL, Java, and most libraries.
