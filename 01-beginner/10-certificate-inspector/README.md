# Project 10 — X.509 Certificate Inspector

> Detect expired, weak, or misconfigured TLS certificates before attackers exploit them.

## What Attack Does This Defend Against?

| MITRE ATT&CK | Technique |
|---|---|
| T1553.004 | Install Root Certificate |
| T1557.002 | ARP Cache Poisoning (MITM via expired cert acceptance) |
| T1040 | Network Sniffing |

Expired certificates break HTTPS. Weak keys and SHA-1 signatures can be forged.
Self-signed certificates are trivially MITMed. This tool finds all three.

## Features

- Inspect certificates from **PEM/DER files** or **live TLS connections**
- Checks: expiry status, days remaining, key type/size, signature algorithm
- Extracts Subject Alternative Names (SANs)
- Flags: expired, expiring < 30 days, weak RSA (< 2048), weak EC (< P-224), DSA, SHA-1, self-signed
- JSON output for integration with monitoring/SIEM systems
- Exit code 1 if any warnings; 0 if clean; 2 if connection fails

## Tech Stack

- Python 3.11+
- `cryptography>=42` for cert parsing
- `ssl` + `socket` stdlib for live TLS inspection

## Architecture

```
cli.py  ──► core.py
             ├── load_from_file()   PEM or DER auto-detect
             ├── load_from_host()   stdlib ssl + socket
             ├── inspect_certificate()  → CertificateReport
             └── _build_warnings()  checks all security properties
```

## Threat Model (STRIDE)

| Threat | Notes |
|---|---|
| Tampering | Expired cert allows MITM — core detection |
| Info Disclosure | Weak keys can be factored/attacked |
| Spoofing | Self-signed certs provide no identity assurance |

## Install & Run on Kali

```bash
cd 01-beginner/10-certificate-inspector
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Inspect a certificate file
cert-inspect file /etc/ssl/certs/ca-certificates.crt

# Inspect a live TLS host
cert-inspect host example.com
cert-inspect host example.com --port 8443

# JSON output for monitoring pipelines
cert-inspect host example.com --json
```

## Privileges

None required for file inspection. Network access required for host inspection.

## Example Output

```
$ cert-inspect host expired.badssl.com
Subject          : CN=*.badssl.com, O=BadSSL, C=US
Issuer           : CN=DigiCert SHA2 Secure Server CA
Valid until      : 2015-04-12  [EXPIRED]
Days remaining   : -3312
Key              : RSA-2048
Signature alg    : sha256

Warnings:
  ! Certificate EXPIRED 3312 days ago
```

## Testing

Tests generate self-signed certificates locally — no network required.

```bash
pip install -r requirements.txt
pytest --cov=src --cov-report=term-missing
```

## What You'll Learn

- `cryptography.x509` API for parsing certificates
- `ssl.create_default_context()` for secure TLS connections
- X.509 field structure: Subject, Issuer, SANs, validity period
- Why certificate monitoring matters in a DevSecOps pipeline

## References

- [MITRE T1553.004](https://attack.mitre.org/techniques/T1553/004/)
- [Mozilla Root Store Policy](https://wiki.mozilla.org/CA/Root_Change_Process)
- [Let's Encrypt — free cert automation](https://letsencrypt.org/)
- [BadSSL — test certificates](https://badssl.com/)
