# Architecture — Input Sanitization Library

## Components

```
core.py   detect_threats(), sanitize_text(), sanitize_filename(), validators
cli.py    Click CLI (scan / sanitize / filename / validate-email / demo)
```

## Pipeline

```
Raw input
  │
  ├─ detect_threats()  →  list[ThreatMatch]  (non-destructive scan)
  │
  └─ sanitize_text()
        strip_null_bytes()
        normalize_unicode()   (NFC + strip control chars)
        strip_html_tags()     (remove all <...> blocks)
        truncate(max_length)
        → SanitizationResult(sanitized, threats, truncated)
```

## Threat Categories

| Category | Detection method |
|----------|-----------------|
| XSS | Regex: `<script>`, `onerror=`, `javascript:`, `<iframe>`, etc. |
| SQLi | Regex: `UNION SELECT`, `OR '1'='1`, `DROP TABLE`, `--`, etc. |
| Path traversal | Regex: `../`, `%2e%2e%2f`, double-encoded variants |
| Command injection | Regex: `;`, `|`, `` ` ``, `$()`, pipe to shell commands |
| Null byte | Character scan for `\x00` |
| Unicode homoglyph | Regex for Cyrillic/Greek lookalikes and smart quotes |
| Oversized | Length check against configurable max |

## Key Design Decisions

- `detect_threats()` is **non-destructive** — callers choose to reject or sanitize
- Sanitization is defence-in-depth, not a replacement for parameterized queries
- `sanitize_filename()` uses allowlist approach (only `[\\w.\\-]` kept)
