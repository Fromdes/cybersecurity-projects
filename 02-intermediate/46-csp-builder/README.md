# Project 46 — CSP Header Builder & Reporter

> Fluent builder for Content-Security-Policy headers with security analysis and violation report parsing.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Cross-Site Scripting (XSS) | T1059.007 | CSP blocks inline scripts and untrusted sources |
| Drive-by Compromise | T1189 | Prevents loading malicious resources from attacker-controlled origins |
| Data from Information Repositories | T1213 | Restricts connect-src to prevent data exfiltration |

## Features

- Fluent `CSPBuilder` API with `strict()` baseline preset
- Nonce and hash source helpers
- Policy analyser — detects `unsafe-inline`, `unsafe-eval`, wildcards, HTTP sources
- Parse existing CSP header strings back to structured objects
- Violation report parser (JSON POST body from browsers)
- CLI: `build`, `analyse`, `parse-report` sub-commands

## Tech Stack

- Python 3.11+, click

## Architecture

```
CSPBuilder (fluent) ──► CSPPolicy (data) ──► .build() ──► HTTP Header string
                                         └──► .analyse() ──► [PolicyWarning]
parse_policy(str) ──────────────────────────► CSPPolicy
CSPViolationReport.from_json() ─────────────► dataclass
```

## Threat Model (STRIDE)

| Threat | Mitigation |
|---|---|
| XSS via injected script | strict-dynamic + nonces block inline execution |
| Data exfiltration | connect-src limited to 'self' |
| Clickjacking | frame-ancestors (added via add()) |
| Mixed content | upgrade-insecure-requests in strict preset |

## Install & Run on Kali

```bash
cd 02-intermediate/46-csp-builder
pip install -e .
csp-builder build --strict --analyse
csp-builder analyse "script-src 'unsafe-inline'"
csp-builder parse-report examples/violation.json
```

## Example Output

```
default-src 'none'; script-src 'self' 'strict-dynamic'; style-src 'self'; \
img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; \
base-uri 'none'; form-action 'self'; upgrade-insecure-requests

[ok] No security warnings found.
```

## Testing

```bash
pytest tests/ -v --cov=project_46
```

## What You'll Learn

- CSP Level 3 directives and source expressions
- Nonce-based vs hash-based inline script allowlisting
- How browsers send violation reports
- Security analysis of CSP policies
