# Project 06 — Diceware Passphrase Generator

> Generate high-entropy memorable passphrases using cryptographic randomness.

## What Attack Does This Defend Against?

| MITRE ATT&CK | Technique |
|---|---|
| T1110 | Brute Force |
| T1110.001 | Password Guessing |

A 6-word EFF Diceware passphrase has ~77.5 bits of entropy — more than a random
16-character password from a 94-character alphabet (~105 bits when compared to
human-chosen passwords which average ~40 bits).

## Features

- **OS CSPRNG** — `secrets.choice()` only (never `random`)
- Bundled 256-word demo list; accepts any EFF-format wordlist
- Configurable word count, separator, number of passphrases
- Entropy estimation with NIST SP 800-63B warning threshold (77 bits)
- EFF large wordlist compatible (one-word-per-line or tab-separated)

## Tech Stack

- Python 3.11+, stdlib only (`secrets`, `math`, `pathlib`)

## Install & Run on Kali

```bash
cd 01-beginner/06-diceware-passphrase-generator
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Generate one passphrase (default: 6 words)
diceware

# Show entropy
diceware --entropy

# Use the full EFF large wordlist for maximum security
curl -sO https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
diceware --wordlist eff_large_wordlist.txt --words 6 --entropy

# Generate 5 passphrases with spaces instead of dashes
diceware --count 5 --separator " "
```

## Privileges

None required.

## Example Output

```
$ diceware --words 6 --entropy
bold-cave-fall-king-grip-horn  [48.0 bits]

WARNING: Entropy 48.0 bits is below the recommended 77 bits.
Consider using the full EFF large wordlist.
```

## Testing

```bash
pip install -r requirements.txt
pytest --cov=src --cov-report=term-missing
```

## What You'll Learn

- Diceware methodology and why word-based passphrases are memorable yet strong
- `secrets.choice()` for cryptographically uniform random selection
- Entropy arithmetic: `n_words × log₂(wordlist_size)`
- EFF wordlist format and how to validate a wordlist

## References

- [EFF Diceware & Passphrases](https://www.eff.org/dice)
- [EFF Large Wordlist](https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt)
- [NIST SP 800-63B §5.1.1](https://pages.nist.gov/800-63-3/sp800-63b.html)
