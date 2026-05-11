# Architecture — Project 02: File Hash Calculator

## Modules

| Module | Responsibility |
|---|---|
| `core.py` | All hashing logic; no I/O |
| `cli.py` | Argument parsing, file lookup, formatted output |

## Key Design Decisions

1. **Single-pass multi-hash** (`hash_file_all`) — opens the file once and updates
   all hashers simultaneously. Avoids re-reading large files N times.

2. **Constant-time comparison** — `hmac.compare_digest` ensures that comparing a
   computed hash to an expected value takes the same time regardless of where the
   first differing byte is. This prevents remote timing attacks in services that
   might wrap this library.

3. **1 MiB chunk size** — balances memory usage with I/O efficiency. Tested to
   handle files larger than available RAM.
