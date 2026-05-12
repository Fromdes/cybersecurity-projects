# Threat Model — Input Sanitization Library

## STRIDE Table

| Threat | Example | Control |
|--------|---------|---------|
| Spoofing | Homoglyph username impersonation | Unicode confusable detection |
| Tampering | SQLi modifies query semantics | SQLi pattern detection; use parameterized queries |
| Repudiation | Malicious input not logged | detect_threats() logs findings at WARNING level |
| Info Disclosure | Path traversal reads /etc/passwd | `sanitize_filename()` strips all `../` and separators |
| Elevation of Privilege | XSS steals admin session | HTML tag stripping, event handler detection |
| DoS | Oversized payload causes OOM | Max-length truncation in sanitize_text() |

## MITRE ATT&CK Coverage

- T1059.007 — JavaScript: XSS patterns and event handler detection
- T1190 — Exploit Public-Facing App: SQLi pattern matching
- T1083 — File and Directory Discovery: path traversal blocking
- T1059 — Command Injection: shell metacharacter detection

## Important Note

This library detects and strips known patterns. It is **defence-in-depth**, not a replacement for:
- Parameterized SQL queries (prevents all SQLi)
- Content Security Policy (prevents XSS execution)
- `os.path.abspath()` + chroot jail (prevents path traversal)
