# Threat Model — Output Encoder

## STRIDE Table

| Threat | Example | Control |
|--------|---------|---------|
| Spoofing | Injected HTML tag impersonates UI | `encode_html_body()` neutralizes all tags |
| Tampering | Stored XSS modifies page DOM | `encode_html_attr()` blocks event handlers |
| Repudiation | No record of encoded output | Logger records context + lengths at DEBUG |
| Info Disclosure | JS injection reads cookies | `encode_js_string()` escapes `</script>` |
| Elevation of Privilege | CSS `expression()` runs JS in old IE | `encode_css_value()` raises on expression |
| DoS | Oversized encoded output | Encoding is ~1:6 worst case; limit input with sanitizer first |

## MITRE ATT&CK Coverage

- T1059.007 — JavaScript: HTML + JS encoders prevent inline script injection
- T1185 — Browser Session Hijacking: attribute encoding blocks event handlers
- T1565.003 — Stored XSS: JSON encoding prevents `</script>` breakout

## Defence-in-Depth Recommendation

```
Input arrives → project 44 (sanitize/detect) → application logic →
Output leaves → project 45 (encode for context) → rendered to user
```

Input sanitization and output encoding together cover the full XSS surface.
