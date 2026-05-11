# Project 16 - Encoding Toolkit
> Encode, decode, and detect Base64/Hex/URL/HTML/ROT13 encodings used to obfuscate malicious payloads.

## What Attack Does This Defend Against? (MITRE ATT&CK IDs)
| Technique | ID | Description |
|---|---|---|
| Obfuscated Files or Information | T1027 | Attackers encode payloads to evade detection |
| Command and Scripting Interpreter – encoded commands | T1059 | PowerShell -EncodedCommand and similar tricks |
| Exfiltration over web service (encoded data) | T1567 | Data hidden in encoded form to bypass DLP |

## Features
- **Encode**: Base64, Base64URL, Base32, Hex, URL-percent, HTML-entity, ROT13
- **Decode**: All of the above with proper padding and error handling
- **Detect**: Structural heuristics to identify likely encoding on unknown strings
- **UTF-8 safe**: Handles non-ASCII input correctly

## Tech Stack
- Python 3.11+, `base64`, `binascii`, `html`, `urllib.parse`, `codecs` (stdlib only)

## Architecture
```
CLI (cli.py)
  encode(data, Encoding) → CodecResult
  decode(data, Encoding) → CodecResult
  detect_encodings(data)  → list[Encoding]
```

## Threat Model (STRIDE)
| Category | Threat | Mitigation |
|---|---|---|
| Info Disclosure | Encoded payload bypasses log scanners | Decode before analysing |
| Tampering | Double-encoded payloads | Iterative decode loop |
| Spoofing | Base64 looks like random data | Use `detect` command first |

## Install & Run on Kali
```bash
cd 01-beginner/16-encoding-toolkit
pip install -e .
encode-toolkit encode "Hello, World!" --encoding base64
encode-toolkit decode "SGVsbG8sIFdvcmxkIQ==" --encoding base64
encode-toolkit encode "<script>alert(1)</script>" --encoding html
encode-toolkit detect "deadbeef1234"
```

## Privileges
No root required.

## Example Output
```
SGVsbG8sIFdvcmxkIQ==
Hello, World!
&lt;script&gt;alert(1)&lt;/script&gt;
Possible encodings:
  - hex
```

## Testing
```bash
pip install -r requirements.txt
pytest --cov=project_16 --cov-report=term-missing
```

## What You'll Learn
- How attackers encode payloads to evade AV/IDS
- Differences between Base64 variants (standard vs URL-safe)
- Python's `codecs` module for text transformations
- Structural heuristics for encoding detection

## References
- [MITRE ATT&CK T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [RFC 4648 – Base16, Base32, Base64 Data Encodings](https://www.rfc-editor.org/rfc/rfc4648)
- [CyberChef (inspiration)](https://gchq.github.io/CyberChef/)
