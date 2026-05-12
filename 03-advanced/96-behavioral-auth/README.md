# Project 96 — Behavioral Authentication PoC

> Continuous authentication using keystroke dynamics — detects impostors even when they know the password.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Valid Accounts | T1078 | Detects credential theft — impostor has password but wrong typing pattern |
| Brute Force | T1110 | Behavioral profile can't be brute-forced without matching the user's motor pattern |
| Adversary-in-the-Middle | T1557 | Replay attacks fail because timing patterns are session-unique |

## Features

- Keystroke dynamics: dwell time, flight time, digraph timing per key pair
- Statistical enrollment from multiple samples (mean + standard deviation)
- Z-score based verification with configurable threshold
- Profile saved to JSON for persistence across sessions
- Synthetic sample generator for testing and demo

## How It Works

1. **Enrollment**: User types passphrase 10+ times → system builds a statistical profile (mean/std per timing feature)
2. **Verification**: User types passphrase once → features extracted → mean z-score computed against profile
3. **Decision**: If mean z-score ≤ threshold → ACCEPTED; otherwise → REJECTED

## Install & Run on Kali

```bash
cd 03-advanced/96-behavioral-auth
pip install -e .
behavioral-auth demo
behavioral-auth enroll --user alice
behavioral-auth verify --user alice
```

## Testing

```bash
pytest tests/ -v --cov=project_96
```
