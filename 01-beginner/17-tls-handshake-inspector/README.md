# Project 17 - TLS Handshake Inspector
> Inspect TLS protocol version, cipher suite, and certificate validity to detect misconfigurations and expiry risks.

## What Attack Does This Defend Against? (MITRE ATT&CK IDs)
| Technique | ID | Description |
|---|---|---|
| Adversary-in-the-Middle | T1557 | Weak TLS allows traffic interception |
| Network Sniffing | T1040 | Unencrypted or weak ciphers expose data |
| Exploit Public-Facing Application | T1190 | Expired/invalid certs signal poor hygiene |

## Features
- **Protocol version**: detects TLS 1.0/1.1 (deprecated) vs TLS 1.2/1.3
- **Cipher suite**: name and key-strength in bits
- **Certificate chain**: subject, issuer, SANs, serial number
- **Expiry tracking**: days until expiry, expired-flag
- **JSON output**: machine-readable for pipeline integration
- **Zero external deps**: uses stdlib `ssl` and `socket`

## Tech Stack
- Python 3.11+, `ssl`, `socket`, `datetime` (stdlib only)

## Architecture
```
CLI (cli.py)
  inspect_host(host, port) → TLSResult
    └─ ssl.SSLContext → ssl.SSLSocket
    └─ _parse_cert(raw_cert) → CertInfo
```

## Threat Model (STRIDE)
| Category | Threat | Mitigation |
|---|---|---|
| Spoofing | Rogue cert / mis-issued cert | Verify CN/SAN matches expected host |
| Tampering | MITM downgrade attack | Require TLS 1.2+ in CI checks |
| Info Disclosure | Expired cert → browser warning bypass | Alert on days_until_expiry < 30 |
| Denial of Service | TLS exhaustion | Out of scope (requires firewall rules) |

## Install & Run on Kali
```bash
cd 01-beginner/17-tls-handshake-inspector
pip install -e .
tls-inspect example.com
tls-inspect example.com --port 443 --json
tls-inspect expired.badssl.com
```

## Privileges
No root required.

## Example Output
```
Host          : example.com:443
Protocol      : TLSv1.3
Cipher        : TLS_AES_256_GCM_SHA384 (256 bits)
Subject       : {'commonName': 'www.example.org'}
Issuer        : {'organizationName': "DigiCert Inc"}
Serial        : 0A3506972FFC42E0D9F9286C...
Not Before    : 2024-01-15T00:00:00+00:00
Not After     : 2025-01-14T23:59:59+00:00
SANs          : DNS:www.example.org, DNS:example.com
Certificate   : OK (expires in 243d)
```

## Testing
```bash
pip install -r requirements.txt
pytest --cov=project_17 --cov-report=term-missing
```

## What You'll Learn
- Python `ssl` module internals and certificate parsing
- TLS version and cipher negotiation
- X.509 certificate structure (CN, SAN, issuer, serial)
- How to detect expired or misconfigured TLS endpoints

## References
- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Python ssl module docs](https://docs.python.org/3/library/ssl.html)
- [NIST SP 800-52 Rev 2 – TLS Guidelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)
