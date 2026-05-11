# Architecture — Project 01: Caesar & Vigenere Cipher Toolkit

## Module Overview

```
src/project_01/
├── __init__.py      Public re-exports
├── __main__.py      python -m entry point
├── cli.py           argparse CLI (I/O only, no cipher logic)
└── core.py          All cipher logic; no I/O
```

## Key Design Decisions

1. **Separation of I/O from logic** — `core.py` never reads stdin or calls `print()`.
   `cli.py` calls core functions and handles all user-facing output.

2. **Chi-squared scoring for crack** — Each of the 25 candidate decryptions is
   scored by chi-squared distance from the known English letter-frequency
   distribution. Lower score = closer to English = better candidate.

3. **Index of Coincidence for Vigenere** — Every `k`-th character (for k = 1..n)
   is extracted as a sub-sequence and its IoC is computed. A key length of `k`
   whose sub-sequence IoC is closest to the English IoC (0.065) is the best hint.

## Data Flow

```
User input (ciphertext, shift/key)
        │
        ▼
    cli.py  (parse args, validate types)
        │
        ▼
    core.py (transform, analyse, score)
        │
        ▼
    cli.py  (format output to stdout)
```
