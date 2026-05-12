# Defensive Cybersecurity Portfolio

> 100 blue-team Python tools, beginner to advanced — built on Kali Linux for cybersecurity internship applications.

[![CI](https://github.com/Fromdes/cybersecurity-projects/actions/workflows/ci.yml/badge.svg)](https://github.com/Fromdes/cybersecurity-projects/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Fromdes/cybersecurity-projects/actions/workflows/codeql.yml/badge.svg)](https://github.com/Fromdes/cybersecurity-projects/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

---

## Overview

This repository is a structured, portfolio-grade collection of **100 defensive (blue-team) cybersecurity tools** written in Python 3.11+, designed to run on Kali Linux. Every project answers the question:

> *"Which attack does this defend against?"* — mapped to MITRE ATT&CK technique IDs.

**No offensive tools.** Every tool here detects, prevents, analyzes, or responds to threats.

---

## Repository Structure

```
cybersecurity-projects/
├── 01-beginner/          # Projects 01-35  — core concepts & CLI tools
├── 02-intermediate/      # Projects 36-75  — detection, auth, threat intel
├── 03-advanced/          # Projects 76-100 — SIEM, EDR, cloud, ML
├── docs/                 # Architecture, glossary, Kali setup, roadmap
├── .github/              # CI/CD workflows, templates, Dependabot
├── pyproject.toml        # Root tool configuration (ruff, mypy, pytest)
├── requirements-dev.txt  # Dev-only dependencies
└── Makefile              # make lint / test / security
```

---

## The 100 Projects

### Level 1 — Beginner (01–35)

| # | Project | MITRE ATT&CK |
|---|---------|-------------|
| [01](01-beginner/01-caesar-vigenere-cipher/) | Caesar & Vigenere Cipher Toolkit | T1027 |
| [02](01-beginner/02-file-hash-calculator/) | File Hash Calculator | T1027, T1553 |
| [03](01-beginner/03-file-integrity-verifier/) | File Integrity Verifier | T1565 |
| [04](01-beginner/04-password-strength-analyzer/) | Password Strength Analyzer | T1110 |
| [05](01-beginner/05-secure-password-generator/) | Secure Password Generator | T1110 |
| [06](01-beginner/06-diceware-passphrase-generator/) | Diceware Passphrase Generator | T1110 |
| [07](01-beginner/07-hibp-client/) | Have-I-Been-Pwned Client | T1586 |
| [08](01-beginner/08-aes256-gcm-encryptor/) | AES-256-GCM File Encryptor | T1022 |
| [09](01-beginner/09-rsa-key-pair-generator/) | RSA Key Pair Generator & File Signer | T1553 |
| [10](01-beginner/10-x509-certificate-inspector/) | X.509 Certificate Inspector | T1587.003 |
| [11](01-beginner/11-totp-hotp-authenticator/) | TOTP/HOTP Authenticator | T1078 |
| [12](01-beginner/12-qr-totp-provisioner/) | QR Code TOTP Provisioner | T1078 |
| [13](01-beginner/13-hmac-authenticator/) | HMAC Message Authenticator | T1565 |
| [14](01-beginner/14-argon2id-password-hasher/) | Argon2id/PBKDF2 Password Hasher | T1110 |
| [15](01-beginner/15-secure-token-generator/) | Secure Token Generator | T1528 |
| [16](01-beginner/16-encoding-toolkit/) | Encoding Toolkit | T1027 |
| [17](01-beginner/17-tls-handshake-inspector/) | TLS Handshake Inspector | T1587.003 |
| [18](01-beginner/18-dns-lookup-tool/) | DNS Lookup & Reverse DNS Tool | T1071.004 |
| [19](01-beginner/19-ip-geolocation-asn/) | IP Geolocation & ASN Lookup | T1590 |
| [20](01-beginner/20-whois-lookup/) | WHOIS Lookup Wrapper | T1590 |
| [21](01-beginner/21-url-parser-validator/) | URL Parser & Validator | T1566 |
| [22](01-beginner/22-phishing-url-detector/) | Phishing URL Heuristic Detector | T1566.002 |
| [23](01-beginner/23-email-header-analyzer/) | Email Header Analyzer (SPF/DKIM/DMARC) | T1566.001 |
| [24](01-beginner/24-file-type-identifier/) | File Type Identifier | T1036 |
| [25](01-beginner/25-steganography-detector/) | Steganography Detector | T1027.003 |
| [26](01-beginner/26-access-log-parser/) | Apache/Nginx Access Log Parser | T1190 |
| [27](01-beginner/27-failed-login-counter/) | Failed Login Counter | T1110 |
| [28](01-beginner/28-file-integrity-monitor/) | File Integrity Monitor (polling) | T1565 |
| [29](01-beginner/29-directory-permission-auditor/) | Directory Permission Auditor | T1222 |
| [30](01-beginner/30-suspicious-process-lister/) | Suspicious Process Lister | T1057 |
| [31](01-beginner/31-listening-port-auditor/) | Listening Port Auditor | T1049 |
| [32](01-beginner/32-hosts-file-tamper-detector/) | Hosts File Tamper Detector | T1565.001 |
| [33](01-beginner/33-browser-history-cleaner/) | Browser History Privacy Cleaner | T1552 |
| [34](01-beginner/34-encrypted-notes-cli/) | Encrypted Notes CLI | T1022 |
| [35](01-beginner/35-encrypted-backup-tool/) | Encrypted Backup Tool | T1022, T1565 |

### Level 2 — Intermediate (36–75)

| # | Project | MITRE ATT&CK |
|---|---------|-------------|
| [36](02-intermediate/36-personal-password-vault/) | Personal Password Vault | T1110, T1555 |
| [37](02-intermediate/37-jwt-validator/) | JWT Validator & Inspector | T1528 |
| [38](02-intermediate/38-oauth2-pkce-client/) | OAuth2 PKCE Client | T1528 |
| [39](02-intermediate/39-rbac-engine/) | RBAC Engine | T1078 |
| [40](02-intermediate/40-abac-policy-engine/) | ABAC Policy Engine | T1078 |
| [41](02-intermediate/41-session-manager/) | Session Manager Service | T1550 |
| [42](02-intermediate/42-webauthn-fido2-verifier/) | WebAuthn/FIDO2 Verifier | T1078 |
| [43](02-intermediate/43-rate-limiter/) | Rate Limiter | T1110, T1499 |
| [44](02-intermediate/44-input-sanitization-library/) | Input Sanitization Library | T1190 |
| [45](02-intermediate/45-output-encoder/) | Output Encoder | T1059 |
| [46](02-intermediate/46-csp-header-builder/) | CSP Header Builder & Reporter | T1059.007 |
| [47](02-intermediate/47-csrf-token-service/) | CSRF Token Service | T1185 |
| [48](02-intermediate/48-secure-file-upload/) | Secure File Upload Service | T1190 |
| [49](02-intermediate/49-secure-rest-api/) | Secure REST API Template | T1190 |
| [50](02-intermediate/50-audit-log-system/) | Audit Log System | T1562 |
| [51](02-intermediate/51-structured-logger/) | Centralized Structured Logger | T1562.002 |
| [52](02-intermediate/52-nmap-result-parser/) | Nmap Result Parser & Diff | T1595 |
| [53](02-intermediate/53-port-scan-detector/) | Port Scan Detection from Logs | T1046 |
| [54](02-intermediate/54-snort-suricata-rule-generator/) | Snort/Suricata Rule Generator | T1190 |
| [55](02-intermediate/55-yara-rule-engine/) | YARA Rule Engine Orchestrator | T1204 |
| [56](02-intermediate/56-ioc-matcher/) | IOC Matcher | T1071 |
| [57](02-intermediate/57-stix-taxii-feed-parser/) | STIX/TAXII Feed Parser | T1071 |
| [58](02-intermediate/58-pcap-analyzer/) | PCAP Analyzer | T1040 |
| [59](02-intermediate/59-dns-dga-detector/) | DNS DGA Detector | T1568.002 |
| [60](02-intermediate/60-linux-process-tree-logger/) | Linux Process Tree Logger | T1057 |
| [61](02-intermediate/61-auditd-log-parser/) | auditd Log Parser | T1562.012 |
| [62](02-intermediate/62-ssh-bruteforce-detector/) | SSH Brute-Force Detection Daemon | T1110.003 |
| [63](02-intermediate/63-ssh-honeypot-logger/) | SSH Honeypot Logger | T1110 |
| [64](02-intermediate/64-http-honeypot-logger/) | HTTP Honeypot Logger | T1190 |
| [65](02-intermediate/65-netflow-ipfix-analyzer/) | NetFlow/IPFIX Analyzer | T1071 |
| [66](02-intermediate/66-tls-config-auditor/) | TLS Configuration Auditor | T1587.003 |
| [67](02-intermediate/67-cert-transparency-monitor/) | Certificate Transparency Monitor | T1587.003 |
| [68](02-intermediate/68-firewall-rule-auditor/) | Firewall Rule Auditor | T1562.004 |
| [69](02-intermediate/69-wifi-deauth-detector/) | WiFi Deauth Detector | T1498 |
| [70](02-intermediate/70-arp-spoofing-detector/) | ARP Spoofing Detector | T1557.002 |
| [71](02-intermediate/71-rogue-dhcp-detector/) | Rogue DHCP Detector | T1557 |
| [72](02-intermediate/72-email-phishing-detector/) | Email Phishing Detector (NLP) | T1566 |
| [73](02-intermediate/73-file-quarantine-service/) | File Quarantine Service | T1204 |
| [74](02-intermediate/74-phishing-url-ml-detector/) | Phishing URL ML Detector | T1566.002 |
| [75](02-intermediate/75-login-anomaly-detector/) | Login Anomaly Detector | T1078 |

### Level 3 — Advanced (76–100)

| # | Project | MITRE ATT&CK |
|---|---------|-------------|
| [76](03-advanced/76-mini-siem-platform/) | Mini SIEM Platform | T1190, T1071 |
| [77](03-advanced/77-lightweight-edr-agent/) | Lightweight EDR Agent | T1059 |
| [78](03-advanced/78-real-time-fim/) | Real-Time FIM (inotify) | T1565 |
| [79](03-advanced/79-static-malware-analyzer/) | Static Malware Analyzer | T1204 |
| [80](03-advanced/80-office-macro-analyzer/) | Office Macro Risk Analyzer | T1204.002 |
| [81](03-advanced/81-forensics-timeline-builder/) | Forensics Timeline Builder | T1070 |
| [82](03-advanced/82-memory-dump-ioc-extractor/) | Memory Dump IOC Extractor | T1055 |
| [83](03-advanced/83-disk-image-hash-custody/) | Disk Image Hash & Chain-of-Custody | T1565 |
| [84](03-advanced/84-secrets-scanner/) | Secrets Scanner | T1552 |
| [85](03-advanced/85-dependency-vulnerability-checker/) | Dependency Vulnerability Checker | T1195.001 |
| [86](03-advanced/86-sbom-generator/) | SBOM Generator | T1195 |
| [87](03-advanced/87-dockerfile-linter/) | Dockerfile Linter & CIS Checker | T1610 |
| [88](03-advanced/88-container-image-scanner/) | Container Image Scanner | T1610 |
| [89](03-advanced/89-kubernetes-rbac-auditor/) | Kubernetes RBAC Auditor | T1078.004 |
| [90](03-advanced/90-terraform-security-scanner/) | Terraform Security Scanner | T1578 |
| [91](03-advanced/91-cloud-iam-analyzer/) | Cloud IAM Policy Analyzer | T1078.004 |
| [92](03-advanced/92-s3-misconfiguration-detector/) | S3 Misconfiguration Detector | T1530 |
| [93](03-advanced/93-zero-trust-gateway/) | Zero Trust Network Gateway | T1078 |
| [94](03-advanced/94-supply-chain-verifier/) | Supply Chain Verifier (SLSA/Sigstore) | T1195 |
| [95](03-advanced/95-dlp-engine/) | DLP Engine | T1048 |
| [96](03-advanced/96-behavioral-auth-poc/) | Behavioral Authentication PoC | T1078 |
| [97](03-advanced/97-encrypted-messaging-library/) | Encrypted Messaging Library (Double Ratchet) | T1040 |
| [98](03-advanced/98-network-ml-anomaly-detector/) | Network ML Anomaly Detector | T1071 |
| [99](03-advanced/99-threat-hunting-toolkit/) | Threat Hunting Toolkit | T1071, T1190 |
| [100](03-advanced/100-gdpr-kvkk-compliance-auditor/) | GDPR/KVKK Compliance Auditor | T1530, T1078 |

---

## Getting Started

### Prerequisites

```bash
# Kali Linux (recommended) or any Debian-based system
sudo apt update && sudo apt install -y python3.11 python3.11-venv python3-pip git

# Clone the repo
git clone https://github.com/Fromdes/cybersecurity-projects.git
cd cybersecurity-projects

# Install dev tools
pip install -r requirements-dev.txt
```

### Running a Project

Each project is self-contained. Navigate to its directory and follow its own README:

```bash
cd 01-beginner/02-file-hash-calculator
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m src.project_02 --help
```

### Running Quality Checks (all projects)

```bash
make lint      # ruff + mypy
make test      # pytest with coverage
make security  # bandit
make all       # all of the above
```

---

## Code Quality

Every project enforces:

- **Type safety** — `mypy --strict`
- **Linting** — `ruff` (E, F, W, B, I, N, UP, S, A, C4, SIM, RUF)
- **Security scanning** — `bandit` (no medium/high findings)
- **Testing** — `pytest` + `pytest-cov` ≥ 80% coverage
- **Docs** — Google-style docstrings on all public APIs

---

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Project Roadmap](docs/ROADMAP.md)
- [Kali Linux Setup Guide](docs/KALI_SETUP.md)
- [Cybersecurity Glossary](docs/GLOSSARY.md)
- [Learning Resources](docs/RESOURCES.md)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions must follow the defensive-only content rules in [CLAUDE.md](CLAUDE.md).

---

## License

[MIT](LICENSE) © 2026
