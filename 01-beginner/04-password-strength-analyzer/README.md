# Project 04 — Password Strength Analyzer

> Evaluate passwords against modern security policies and give actionable improvement advice.

## What Attack Does This Defend Against?

| MITRE ATT&CK | Technique |
|---|---|
| T1110 | Brute Force |
| T1110.001 | Password Guessing |
| T1110.002 | Password Cracking |
| T1589.001 | Gather Victim Credentials |

Weak passwords are the #1 entry point for breaches. This tool quantifies weakness.

## Features

- Shannon entropy estimation (bits) based on character-class pool size
- Detects keyboard walks (`qwerty`, `asdf`, `1qaz2wsx`), date patterns, repeated chars
- 0–4 strength score with labeled tiers (Very Weak → Very Strong)
- Actionable suggestions for each missing character class
- JSON output for integration into registration/authentication pipelines
- Reads from args, `--stdin`, or interactive `getpass` prompt
- Exits with code 0 (strong), 1 (weak) — usable as a pre-commit hook

## Tech Stack

- Python 3.11+, stdlib only (`math`, `re`, `string`, `getpass`, `dataclasses`)

## Architecture

```
cli.py ──► core.py
            ├── analyze_password()   → PasswordAnalysis
            ├── _calculate_entropy() (length * log2(pool))
            ├── _generate_feedback() (warnings + suggestions)
            └── _calculate_score()   (0–4 based on entropy + penalties)
```

## Threat Model (STRIDE)

| Threat | Notes |
|---|---|
| Information Disclosure | Password is never stored or logged |
| Tampering | Score output can be spoofed; integrate into server-side validation |
| Brute Force | Weak passwords still crackable; use Project 05 to generate strong ones |

## Install & Run on Kali

```bash
cd 01-beginner/04-password-strength-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Analyze a password from the command line
password-analyze "MyP@ssw0rd2024"

# JSON output
password-analyze "hunter2" --json

# Pipe from stdin (no echo in terminal)
echo "SomePassw0rd!" | password-analyze --stdin
```

## Privileges

None required.

## Example Output

```
Strength : Strong  ████████  (3/4)
Length   : 14 characters
Entropy  : 91.8 bits
Classes  : lower, upper, digits, special

Suggestions:
  • Use at least 16 characters for strong security
```

## Testing

```bash
pip install -r requirements.txt
pytest --cov=src --cov-report=term-missing
```

## What You'll Learn

- Shannon entropy calculation for passwords
- Regex-based pattern detection
- `getpass` for secure password input in CLI tools
- `dataclasses.dataclass(frozen=True)` for immutable result objects
- Exit codes as machine-readable signals

## References

- [NIST SP 800-63B Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [MITRE T1110](https://attack.mitre.org/techniques/T1110/)
- [zxcvbn — realistic password strength estimator](https://github.com/dropbox/zxcvbn)
