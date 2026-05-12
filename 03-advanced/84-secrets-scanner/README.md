# Project 84 — Secrets Scanner

> Scans source code repositories for hardcoded secrets, API keys, passwords, and credentials using 19 regex-based rules with severity scoring and CI-friendly exit codes.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Unsecured Credentials | T1552 | Detects hardcoded credentials in files |
| Credentials from Files | T1552.001 | Finds API keys, tokens in config/source files |
| Cloud Instance Metadata | T1552.005 | Detects hardcoded cloud service credentials |

## Features

- 19 built-in rules: AWS, GitHub, Google, Stripe, Slack, private keys, JWTs, DB URLs, etc.
- Allowlist patterns to reduce false positives (test/example/fake/dummy values)
- `# nosec` inline suppression support
- Partial value redaction in output (shows only first/last 4 chars)
- Recursive directory scanning with path skip list (node_modules, .git, venv)
- CI-friendly `--exit-code` flag
- JSON output for pipeline integration

## Tech Stack

- Python 3.11+, re, click (zero external runtime deps)

## Architecture

```
Target (file/dir)
    │
    ▼
SecretsScanner.scan_file()
    │
    ├── per line:
    │   ├── length check (skip > 2000 chars)
    │   ├── allowlist check (skip test/example/nosec lines)
    │   └── apply 19 SecretRule patterns
    │
    └── SecretFinding (rule, severity, file, line, redacted value)
         │
         ▼
JSON output / CLI display
```

## Threat Model (STRIDE)

| STRIDE | Risk | Mitigation |
|---|---|---|
| Info Disclosure | Secrets in output report | Values redacted to first/last 4 chars |
| Tampering | Scanner bypass via obfuscation | Multi-rule coverage; entropy checks |
| DoS | Huge files exhaust memory | Line-by-line streaming; length cap |

## Install & Run on Kali

```bash
cd 03-advanced/84-secrets-scanner
pip install -e .
secrets-scanner rules
secrets-scanner scan /path/to/repo
secrets-scanner scan /path/to/repo -o findings.json --min-severity HIGH
secrets-scanner scan app.py --exit-code  # returns 1 if secrets found
```

## Privileges

No privileges required.

## Example Output

```
[CRITICAL] PRIVATE_KEY_HEADER — deploy/prod.pem:1
  -----BEGIN RSA PRIVATE KEY-----
[HIGH]     GENERIC_PASSWORD — config/database.py:12
  db_password = "MyStr0ngPassw0rd!"
Scanned 143 file(s): 2 with findings, 3 total secret(s)
```

## Testing

```bash
pytest tests/ -v --cov=project_84
```

## What You'll Learn

- Regex-based secret detection patterns
- False-positive reduction with allowlists
- CI/CD security gate integration

## References

- [MITRE T1552](https://attack.mitre.org/techniques/T1552/)
- [GitLeaks](https://github.com/gitleaks/gitleaks)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
