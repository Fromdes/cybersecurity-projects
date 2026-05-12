# Project 54 — Snort/Suricata Rule Generator

> Fluent builder for Snort/Suricata IDS rules with content matching, PCRE, threshold, and preset templates.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Exploit Public-Facing Application | T1190 | SQLi / XSS detection rules |
| Brute Force | T1110 | SSH brute-force threshold rule |
| Network Service Discovery | T1046 | Port sweep detection rules |

## Features

- Fluent `RuleBuilder` API
- Full Snort 2.x / Suricata 6+ rule syntax
- Content options (nocase, offset, depth, http_uri, http_header)
- PCRE options
- Threshold (rate-limiting) option
- Preset templates: SQL injection, XSS, SSH brute-force
- Rule validator (action, protocol, SID, msg)

## Install & Run

```bash
cd 02-intermediate/54-snort-rule-generator
pip install -e .
snort-rule-gen presets --type sqli
snort-rule-gen presets --type xss
snort-rule-gen build --msg "Custom rule" --content "evil-pattern"
```

## Testing

```bash
pytest tests/ -v --cov=project_54
```

## What You'll Learn

- Snort/Suricata rule syntax
- Content matching and PCRE in IDS rules
- Threshold-based detection
- Builder pattern for complex structured output
