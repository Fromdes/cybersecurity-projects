# Architecture — Project 06: Diceware Passphrase Generator

## Why Diceware?

A passphrase like `bold-cave-fall-king-grip-horn` is:
- **Memorable** — real English words
- **High entropy** — 48+ bits with demo list, 77+ bits with EFF large list
- **Unguessable** — each word chosen independently with CSPRNG

## Entropy Table

| Wordlist size | 4 words | 6 words | 8 words |
|---|---|---|---|
| 256 (demo) | 32 bits | 48 bits | 64 bits |
| 1296 (EFF short) | 42.8 bits | 64.2 bits | 85.6 bits |
| 7776 (EFF large) | 51.7 bits | 77.5 bits | **103.4 bits** |

## Module Layout

```
_wordlist.py   Bundled 256-word demo constant (never changes)
core.py        load_wordlist(), generate_passphrase(), passphrase_entropy()
cli.py         argparse wrapper around core functions
```

## Security Properties

- Words chosen with `secrets.choice()` — each choice is independently uniform
- No biases introduced by rejection sampling (unlike password generators)
- Output is deterministic in length: always exactly `word_count` words
