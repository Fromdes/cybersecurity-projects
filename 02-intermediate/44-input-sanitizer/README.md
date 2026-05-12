# Project 44 — Input Sanitization Library

> Detect and strip XSS, SQL injection, path traversal, command injection, null bytes, and Unicode homoglyphs from untrusted input — defence-in-depth for every trust boundary.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Defence |
|-----------|----|---------|
| JavaScript injection (XSS) | T1059.007 | Script tag, event handler, `javascript:` pattern detection |
| Exploit Public-Facing App (SQLi) | T1190 | UNION SELECT, tautology, DROP, time-based injection patterns |
| File and Directory Discovery | T1083 | Path traversal `../` blocking in `sanitize_filename()` |
| Command Injection | T1059 | Shell metacharacter and pipe command detection |

## Features

- **`detect_threats()`** — non-destructive scan returning `list[ThreatMatch]`
- **`sanitize_text()`** — full pipeline: null bytes → NFC normalize → strip HTML → truncate
- **`sanitize_filename()`** — allowlist-based, strips all `../`, separators, leading dots
- **`validate_email()`** / **`validate_integer()`** — typed validators with range checks
- Unicode homoglyph detection (Cyrillic/Greek lookalikes, smart quotes)
- All patterns non-destructive by default — callers decide to reject or clean
- 7 threat categories with position metadata

## Tech Stack

- Python 3.11+, stdlib only (re, unicodedata), click

## Install & Run

```bash
cd 02-intermediate/44-input-sanitizer
pip install -e .

input-sanitizer demo
input-sanitizer scan "<script>alert(1)</script>"
input-sanitizer sanitize "' UNION SELECT * FROM users--"
input-sanitizer filename "../../etc/passwd"
input-sanitizer validate-email user@example.com
```

## Testing

```bash
pytest --cov=project_44 --cov-report=term-missing
```

## What You'll Learn

- OWASP Top 10: Injection and XSS categories
- Regex-based threat detection patterns
- Defence-in-depth: why sanitization supplements but doesn't replace parameterized queries
- Unicode homoglyph attacks

## References

- OWASP Input Validation Cheat Sheet
- MITRE T1059.007, T1190, T1083
