# Threat Model — Threat Hunting Toolkit

## STRIDE Analysis

| Threat | Component | Mitigation |
|---|---|---|
| Spoofing | IOC values | Case-insensitive string matching; no DNS resolution |
| Tampering | Hunt rules | Rules loaded as immutable frozen dataclasses |
| Repudiation | Detections | JSON report with file paths, line numbers, content |
| Information Disclosure | Log content | matched line_content truncated to 200 chars in report |
| DoS | Large log dirs | Per-file streaming read; skip binary extensions |
| Elevation of Privilege | Rule injection | JSON rule parser; no eval/exec of rule content |

## Hunting Methodology

1. **Atomic indicators**: Pattern match on individual lines (HUNT-001 through HUNT-010)
2. **IOC correlation**: Check logs against threat intel IOC lists
3. **Contextual hunting**: Rules can require multiple patterns to co-occur (condition: all)
