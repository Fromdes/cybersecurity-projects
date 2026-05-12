# Project 45 — Output Encoder

> Context-aware output encoding for HTML body, HTML attributes, JavaScript strings, URL parameters, CSS values, JSON, and shell arguments — the second half of XSS prevention.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Defence |
|-----------|----|---------|
| JavaScript injection (XSS) | T1059.007 | HTML + JS encoders neutralize all script patterns |
| Browser Session Hijacking | T1185 | Attribute encoding blocks `onerror=` and similar |
| Stored XSS (data manipulation) | T1565.003 | JSON encoder escapes `</script>` breakout |
| CSS expression injection | — | `encode_css_value()` rejects `expression()` |

## Features

- **8 encoding contexts**: `html_body`, `html_attr`, `js_string`, `url_param`, `url_path`, `css_value`, `json_value`, `shell_arg`
- **`encode(value, context)`** dispatcher — single call, right encoding every time
- HTML attribute encoder more aggressive than body encoder (also encodes `/ = \``)
- JS encoder escapes `</script>` as `\\u003C` to prevent script block breakout
- JSON encoder escapes `< > /` for inline-`<script>` embedding
- CSS encoder rejects `expression()`, `javascript:`, `vbscript:`
- Shell encoder uses single-quote wrapping with `'"'"'` for embedded quotes
- `compare` command shows all encodings side by side

## Tech Stack

- Python 3.11+, stdlib only (html, json, re, urllib.parse), click

## Install & Run

```bash
cd 02-intermediate/45-output-encoder
pip install -e .

output-encoder demo
output-encoder encode "<script>alert(1)</script>" --context html_body
output-encoder encode "hello world" --context url_param
output-encoder compare "<script>alert('xss')</script>"
```

## Testing

```bash
pytest --cov=project_45 --cov-report=term-missing
```

## What You'll Learn

- Why output context determines the correct encoding function
- The difference between HTML body, attribute, and JS string contexts
- `</script>` injection via JSON in `<script>` blocks
- CSS `expression()` attack (IE legacy, still in CTF challenges)

## References

- OWASP XSS Prevention Cheat Sheet
- OWASP DOM-Based XSS Prevention Cheat Sheet
- MITRE T1059.007, T1185
