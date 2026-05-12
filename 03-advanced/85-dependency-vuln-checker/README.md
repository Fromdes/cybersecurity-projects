# Project 85 — Dependency Vulnerability Checker

> Parses Python (requirements.txt), Node.js (package.json), and Go (go.mod) dependency manifests, then queries the OSV.dev API to report known CVEs with severity, CVSS scores, and fixed versions.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Supply Chain Compromise | T1195.001 | Detects vulnerable third-party dependencies |
| Exploit Public-Facing Application | T1190 | Identifies CVEs in web framework dependencies |

## Features

- Parses requirements.txt, package.json, go.mod
- Batch queries OSV.dev API (open-source, no API key required)
- Severity/CVSS score extraction
- Fixed version recommendations
- CI-friendly `--exit-code` flag (returns 1 if vulnerabilities found)
- `--offline` mode for dry-run/testing
- JSON report output
- Single package point query

## Tech Stack

- Python 3.11+, urllib, json, re, click (zero external runtime deps)

## Architecture

```
Manifest file
    │
    ▼ detect_and_parse()
Dependency list
    │
    ▼ query_osv_batch()
OSV.dev API (HTTPS POST)
    │
    ▼ DependencyResult list
    │
    ├── CLI display (severity-colored)
    └── JSON report
```

## Threat Model (STRIDE)

| STRIDE | Risk | Mitigation |
|---|---|---|
| Spoofing | Fake OSV API responses | Use HTTPS; verify TLS certificate |
| Tampering | Modified requirements.txt | Pair with FIM / git commit hash verification |
| Info Disclosure | Dependency list exposes tech stack | Restrict report access |
| DoS | API rate limiting | Batch queries; respect rate limits |

## Install & Run on Kali

```bash
cd 03-advanced/85-dependency-vuln-checker
pip install -e .
dep-vuln-checker check requirements.txt
dep-vuln-checker check package.json -o vulns.json --exit-code
dep-vuln-checker query requests 2.0.0 --ecosystem PyPI
dep-vuln-checker check go.mod
```

## Privileges

No privileges required. Outbound HTTPS to api.osv.dev needed.

## Example Output

```
Checking 47 dependencies from requirements.txt …
Results: 47 packages checked, 2 vulnerable, 3 CVE(s)

requests 2.0.0 (PyPI)
  [HIGH]     PYSEC-2023-074 — CRLF injection vulnerability
             Fix: upgrade to 2.28.2
  [MODERATE] PYSEC-2021-059 — Certificate verification bypass
             Fix: upgrade to 2.25.1
```

## Testing

```bash
pytest tests/ -v --cov=project_85
```

## What You'll Learn

- OSV (Open Source Vulnerabilities) API integration
- Multi-ecosystem dependency manifest parsing
- Supply chain vulnerability management

## References

- [OSV.dev](https://osv.dev/)
- [MITRE T1195.001](https://attack.mitre.org/techniques/T1195/001/)
- [OSV Schema](https://ossf.github.io/osv-schema/)
