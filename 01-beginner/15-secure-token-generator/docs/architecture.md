# Architecture — Project 15: Secure Token Generator

## Module Layout
```
src/project_15/
  core.py   — token generation logic (TokenFormat, TokenResult, generate_token, estimate_entropy)
  cli.py    — argparse CLI (generate / entropy subcommands)
```

## Data Flow
```
User → CLI → generate_token(fmt, byte_length)
                └─ secrets.token_bytes(n)   [HEX / BASE64URL]
                └─ secrets.choice(charset)  [ALPHANUM]
                └─ uuid.uuid4()             [UUID4]
             → TokenResult(token, format, entropy_bits, byte_length)
           → stdout
```

## Key Design Decisions
- `secrets` module (CSPRNG) instead of `random` (PRNG) — prevents statistical prediction
- `TokenResult` is a frozen dataclass — immutable, hashable, safe to log
- Entropy is calculated after generation and reported to the user
- UUID4 always uses 122 bits regardless of `byte_length` argument
