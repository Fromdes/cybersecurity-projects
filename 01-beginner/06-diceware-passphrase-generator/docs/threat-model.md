# Threat Model — Project 06: Diceware Passphrase Generator

## STRIDE

| Threat | Notes |
|---|---|
| Brute Force | 77-bit EFF passphrase takes ~10^23 guesses — infeasible |
| Dictionary Attack | Each word from 7776-word pool; combinations are astronomically large |
| Information Disclosure | Passphrase not stored; pipe directly to password manager |
| Tampering | If wordlist file is modified, passphrase entropy may decrease |
| Repudiation | N/A — offline generator |

## Key Risk: Small Wordlist

The bundled 256-word demo list gives only 48 bits of entropy for 6 words —
below the NIST 77-bit recommendation. Always use the EFF large wordlist
(7776 words) for real credentials.
