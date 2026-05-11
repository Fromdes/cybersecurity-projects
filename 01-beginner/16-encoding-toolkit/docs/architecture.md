# Architecture — Project 16: Encoding Toolkit

## Module Layout
```
src/project_16/
  core.py   — codec logic (Encoding enum, encode, decode, detect_encodings)
  cli.py    — argparse CLI (encode / decode / detect subcommands)
```

## Data Flow
```
User → CLI → encode(data, Encoding) → _dispatch_encode(data, raw, enc)
                                         └─ base64/hex/url/html/rot13
                                      → CodecResult(output, encoding, "encode")
                                      → stdout

         decode(data, Encoding) → _dispatch_decode(data, enc)
                                     └─ _decode_inner → output or ValueError
                                  → CodecResult(output, encoding, "decode")

         detect_encodings(data) → candidates: list[Encoding]
                                     └─ _check_hex, _check_base32, _check_base64, _check_url
```

## Key Design Decisions
- `match` structural pattern matching (Python 3.10+) for clean dispatch
- `_decode_inner` separates logic from error wrapping in `_dispatch_decode`
- Detection is heuristic (structural, not semantic); results may overlap
- ROT13 is symmetric — `encode` and `decode` are identical operations
