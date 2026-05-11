# Project 05 — Secure Password Generator

> Generate cryptographically random passwords using the OS CSPRNG (`secrets` module).

## What Attack Does This Defend Against?

| MITRE ATT&CK | Technique |
|---|---|
| T1110.001 | Password Guessing |
| T1110.002 | Password Cracking |

Predictable passwords (from `random` module or weak generators) are trivially cracked.
This tool uses the OS cryptographic random source — the same source as SSL keys.

## Features

- **OS CSPRNG** — `secrets.choice()` (never `random`)
- Configurable length (default 16), character classes, ambiguous-char exclusion
- `--require-each-class` (default on) — guarantees at least one lower, upper, digit, special
- Generate multiple unique passwords in one call
- Entropy estimate in bits
- Pipe-friendly: one password per line

## Tech Stack

- Python 3.11+, stdlib only (`secrets`, `string`, `math`, `dataclasses`)

## Install & Run on Kali

```bash
cd 01-beginner/05-secure-password-generator
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Single 16-character password
password-gen

# 5 passwords, 24 chars, with entropy estimate
password-gen --count 5 --length 24 --entropy

# No ambiguous characters (good for typed passwords)
password-gen --no-ambiguous --length 20

# Only digits and uppercase (PIN-style)
password-gen --no-lower --no-special --length 8
```

## Privileges

None required.

## Example Output

```
$ password-gen --count 3 --entropy
K#m9vT2@pLx!BqNe  [104.2 bits]
7zR$wJn4&YcH!sQf  [104.2 bits]
bM@3kXv!9WrN#2pT  [104.2 bits]
```

## Testing

```bash
pip install -r requirements.txt
pytest --cov=src --cov-report=term-missing
```

## What You'll Learn

- `secrets` module vs `random` — why CSPRNG matters
- Rejection sampling to guarantee character-class coverage
- `dataclasses.dataclass(frozen=True)` for configuration objects
- Entropy estimation for password policies

## References

- [Python `secrets` module docs](https://docs.python.org/3/library/secrets.html)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [MITRE T1110.001](https://attack.mitre.org/techniques/T1110/001/)
