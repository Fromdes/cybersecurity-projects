# Threat Model — Project 16: Encoding Toolkit

## Assets
- Ability to decode attacker payloads for analysis
- Correct identification of obfuscated data in logs/traffic

## Threat Actors
- Malware authors encoding C2 commands
- Phishing kits encoding payloads to bypass URL scanners

## STRIDE Analysis
| Threat | Example | Mitigation |
|---|---|---|
| Spoofing | Base64 string looks like random data | Use `detect` to identify encoding before analysis |
| Tampering | Double/triple encoding to evade single-pass scan | Iterate decode until output is stable ASCII |
| Info Disclosure | Tool itself sends data to external service | All processing is local; no network calls |
| Elevation | Decoded payload executed by analyst tool | Never execute decoded output; treat as untrusted |

## Assumptions
- Input data is provided by analyst, not executed
- Decoded output is reviewed, not auto-executed
- Tool is used for analysis, not payload generation
