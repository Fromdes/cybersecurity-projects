# Project 01 — Caesar & Vigenere Cipher Toolkit

> Understand and break classical substitution ciphers to appreciate why modern encryption matters.

## What Attack Does This Defend Against?

| MITRE ATT&CK | Technique |
|---|---|
| T1027 | Obfuscated Files or Information |
| T1600 | Weaken Encryption |

Classical ciphers are still found in CTF challenges, legacy systems, and insider-threat scenarios.
This toolkit teaches you to **detect and break** them — the foundation of cryptanalysis.

## Features

- **Caesar cipher** — encrypt, decrypt, or brute-force crack all 25 shifts
- **Vigenere cipher** — encrypt / decrypt with any alphabetic key
- **Frequency analysis** — letter-frequency bar chart or JSON output
- **Index of Coincidence** — key-length estimation for Vigenere ciphertext
- **Shannon entropy** estimator
- Zero third-party runtime dependencies (stdlib only)

## Tech Stack

- Python 3.11+, stdlib only (`string`, `math`)
- argparse CLI
- pytest + pytest-cov for tests

## Architecture

```
cli.py  ──► core.py
             ├── CaesarCipher
             ├── VigenereCipher
             ├── frequency_analysis()
             ├── caesar_crack()          (chi-squared scoring)
             └── vigenere_key_length_hint()  (Index of Coincidence)
```

## Threat Model (STRIDE)

| Threat | Description | Mitigation |
|---|---|---|
| **S**poofing | Attacker claims a message is from a trusted sender | Use HMAC/signatures (see Project 13) |
| **T**ampering | Ciphertext modified in transit | Authenticated encryption (see Project 08) |
| **R**epudiation | Sender denies encrypting a message | Digital signatures (see Project 09) |
| **I**nformation Disclosure | Frequency analysis cracks Caesar in seconds | Use AES-256-GCM (Project 08) instead |
| **D**enial of Service | N/A for offline tool | — |
| **E**levation of Privilege | N/A for offline tool | — |

## Install & Run on Kali

```bash
cd 01-beginner/01-caesar-vigenere
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Caesar encrypt
cipher-toolkit caesar "Hello World" --shift 13 --encrypt

# Crack an intercepted Caesar ciphertext
cipher-toolkit caesar "Khoor Zruog" --crack

# Vigenere encrypt / decrypt
cipher-toolkit vigenere "Attack at dawn" --key SECRET --encrypt
cipher-toolkit vigenere "Sxnrpz ey hied" --key SECRET --decrypt

# Letter-frequency analysis
cipher-toolkit freq "The quick brown fox jumps over the lazy dog"
cipher-toolkit freq "Encrypted text here" --json
```

## Privileges

None required. Runs as any user.

## Example Output

```
$ cipher-toolkit caesar "Khoor Zruog" --crack
Top crack candidates (best English-frequency match first):
  shift= 3: Hello World
  shift=16: Uryyb Jbeyq
  shift= 9: Bytte Metle
  ...
```

## Testing

```bash
pip install -r requirements.txt
pytest --cov=src --cov-report=term-missing
```

## What You'll Learn

- How Caesar and Vigenere ciphers work (and why they fail)
- Chi-squared statistical scoring to rank decryption candidates
- Index of Coincidence for polyalphabetic cipher analysis
- Why modern symmetric encryption (AES) is exponentially harder to crack

## References

- [MITRE T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [Practical Cryptography – Frequency Analysis](http://practicalcryptography.com/cryptanalysis/letter-frequency-analysis/)
- [EFF – Why strong encryption matters](https://www.eff.org/issues/surveillance-and-technology)
