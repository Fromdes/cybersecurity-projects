# Project 07 — Have-I-Been-Pwned Client

> Check passwords against 10+ billion leaked credentials without sending your password to anyone.

## What Attack Does This Defend Against?

| MITRE ATT&CK | Technique |
|---|---|
| T1589.001 | Gather Victim Identity Information: Credentials |
| T1110.002 | Password Cracking |

Credential stuffing attacks reuse leaked passwords from other sites. Knowing
whether your password has been leaked is the first step to protecting your accounts.

## Features

- **k-Anonymity** — only the first 5 hex characters of the SHA-1 hash are sent
  to the HIBP API; your full password and hash never leave your machine
- Check by password (hashed locally) or pre-computed SHA-1 hash
- Returns exact breach count (0 = safe, N = appeared N times in breaches)
- Exit codes: 0 = safe, 1 = pwned, 2 = network error
- `--stdin` for scripted/pipeline use

## Tech Stack

- Python 3.11+
- `requests>=2.32` for HTTPS API calls

## How k-Anonymity Works

```
password → SHA-1 → "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
                         ↑────┘↑──────────────────────────────┘
                    sent to API     stays local, compared locally
```

The API returns all hashes starting with `5BAA6` — hundreds of entries —
so Troy Hunt's server cannot determine which specific hash you checked.

## Install & Run on Kali

```bash
cd 01-beginner/07-hibp-client
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Check a password (interactive prompt — nothing echoed to terminal)
hibp-check password

# Check directly (avoid using real passwords in shell history!)
hibp-check password --stdin <<< "MyPassword123"

# Check a pre-computed hash
hibp-check hash 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
```

## Privileges

None required. Requires internet access.

## Example Output

```
$ hibp-check password
Password to check: ****
PWNED — found 10,013,014 times in known data breaches!
Change this password immediately.
```

## Testing

All tests mock the network — no real HIBP API calls during test runs.

```bash
pip install -r requirements.txt
pytest --cov=src --cov-report=term-missing
```

## What You'll Learn

- SHA-1 hashing and k-anonymity for privacy-preserving API queries
- `requests.Session` and dependency injection for testable network code
- `getpass` for secure password input
- Mocking HTTP responses with `unittest.mock`

## References

- [HIBP k-anonymity API docs](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- [Troy Hunt — k-anonymity blog post](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/)
- [MITRE T1589.001](https://attack.mitre.org/techniques/T1589/001/)
