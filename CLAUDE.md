# CLAUDE.md — Defensive Cybersecurity Portfolio

Read this file at the start of every session.

---

## About the Project
- 100 defensive (blue-team) cybersecurity projects
- All Python 3.11+, runnable on Kali Linux
- Owner: first-year programming student, knows Java, learning Python alongside cybersecurity
- Goal: portfolio-grade GitHub repository for job applications

---

## Strict Content Rules (NEVER VIOLATE)

NEVER build offensive tools: keyloggers, port scanners, password crackers, brute-forcers, packet injectors, deauth tools, ARP spoofers, exploit code, malware, ransomware, rootkits, reverse shells, SQL injection tools, XSS payload generators, phishing kits, credential stealers.

ALWAYS build defensive equivalents instead:
- keylogger -> host monitor for keyboard/process anomalies
- port scanner -> log-based scan detection engine
- password cracker -> password policy enforcer + HIBP leaked-password checker
- SQLi tool -> SQLi detection rules + parameterized query examples
- XSS tool -> input sanitizer library
- reverse shell -> EDR agent for shell command anomaly detection
- deauth tool -> passive WiFi monitor that detects deauth attacks
- malware sample -> static malware analyzer + YARA rule engine

Every project must answer: "Which attack does this defend against?" with MITRE ATT&CK technique IDs.

If output filtering blocks you: STOP, tell me which project and file triggered it, propose a defensive reframing, wait for approval. NEVER leave half-finished files.

---

## Tech Stack
- Python 3.11+ (only)
- CLI by default (argparse or click); Flask/FastAPI only when project explicitly needs a web UI (SIEM, DLP, compliance auditor)
- Standard libs: cryptography, hashlib, secrets, requests, scapy, paramiko, dnspython, python-magic, pefile, yara-python, volatility3, oletools, psutil, watchdog, pyinotify, pyotp, PyJWT, authlib, fido2, argon2-cffi, zxcvbn, bleach, fastapi, flask, redis, scikit-learn, pandas, numpy, sslyze, python-libnmap, stix2, taxii2-client, boto3
- Each project has its own pyproject.toml and pinned requirements.txt

---

## Code Quality Standards
- Type hints everywhere (mypy --strict must pass)
- ruff linting must pass with strict ruleset (E, F, W, B, I, N, UP, S, A, C4, SIM, RUF)
- bandit security linting must pass with no medium/high findings
- Google-style docstrings on every public function/class
- Functions under 30 lines; modules under 300 lines
- No magic numbers/strings, use named constants
- Specific exceptions only; never bare except; never swallow exceptions
- stdlib logging with structured formatter; print() forbidden except in CLI output paths
- Configuration via YAML/TOML or env vars; no hardcoding
- Input validation at every trust boundary (pydantic)
- Secrets via env vars or .env (gitignored); never in code
- Prefer immutability (frozen dataclasses, tuples)
- pytest + pytest-cov + pytest-mock; AAA pattern; 80%+ coverage target
- Each project must pass: make lint test security with zero errors

---

## Repository Structure

```
Root:
  README.md, LICENSE (MIT), .gitignore, .editorconfig, CONTRIBUTING.md,
  CODE_OF_CONDUCT.md, SECURITY.md, CHANGELOG.md, pyproject.toml,
  requirements-dev.txt, Makefile,
  .github/workflows/ (ci.yml, codeql.yml, dependency-review.yml),
  .github/ISSUE_TEMPLATE/,
  .github/PULL_REQUEST_TEMPLATE.md,
  .github/dependabot.yml,
  docs/ (ROADMAP.md, RESOURCES.md, GLOSSARY.md, KALI_SETUP.md, ARCHITECTURE.md),
  01-beginner/   (projects 01-35)
  02-intermediate/ (projects 36-75)
  03-advanced/   (projects 76-100)

Each project NN-name/:
  README.md
  pyproject.toml
  requirements.txt
  src/project_nn/
    __init__.py
    __main__.py
    cli.py
    core.py
  tests/
    test_core.py
    test_cli.py
  docs/
    architecture.md
    threat-model.md
  examples/
  .gitignore
```

---

## Per-Project README Template

```
# Project NN - [Name]
> One-sentence pitch.
## What Attack Does This Defend Against? (MITRE ATT&CK IDs)
## Features
## Tech Stack
## Architecture
## Threat Model (STRIDE table)
## Install & Run on Kali
## Privileges (root needed?)
## Example Output
## Testing
## What You'll Learn
## References
```

---

## The 100 Projects (build in this exact order)

### LEVEL 1 - BEGINNER (01-35)

01. Caesar & Vigenere Cipher Toolkit
02. File Hash Calculator
03. File Integrity Verifier
04. Password Strength Analyzer
05. Secure Password Generator
06. Diceware Passphrase Generator
07. Have-I-Been-Pwned Client
08. AES-256-GCM File Encryptor
09. RSA Key Pair Generator & File Signer
10. X.509 Certificate Inspector
11. TOTP/HOTP Authenticator
12. QR Code TOTP Provisioner
13. HMAC Message Authenticator
14. Argon2id/PBKDF2 Password Hasher
15. Secure Token Generator
16. Encoding Toolkit
17. TLS Handshake Inspector
18. DNS Lookup & Reverse DNS Tool
19. IP Geolocation & ASN Lookup
20. WHOIS Lookup Wrapper
21. URL Parser & Validator
22. Phishing URL Heuristic Detector
23. Email Header Analyzer (SPF/DKIM/DMARC)
24. File Type Identifier
25. Steganography Detector
26. Apache/Nginx Access Log Parser
27. Failed Login Counter
28. File Integrity Monitor (polling)
29. Directory Permission Auditor
30. Suspicious Process Lister
31. Listening Port Auditor
32. Hosts File Tamper Detector
33. Browser History Privacy Cleaner
34. Encrypted Notes CLI
35. Encrypted Backup Tool

### LEVEL 2 - INTERMEDIATE (36-75)

36. Personal Password Vault
37. JWT Validator & Inspector
38. OAuth2 PKCE Client
39. RBAC Engine
40. ABAC Policy Engine
41. Session Manager Service
42. WebAuthn/FIDO2 Verifier
43. Rate Limiter
44. Input Sanitization Library
45. Output Encoder
46. CSP Header Builder & Reporter
47. CSRF Token Service
48. Secure File Upload Service
49. Secure REST API Template
50. Audit Log System
51. Centralized Structured Logger
52. Nmap Result Parser & Diff
53. Port Scan Detection from Logs
54. Snort/Suricata Rule Generator
55. YARA Rule Engine Orchestrator
56. IOC Matcher
57. STIX/TAXII Feed Parser
58. PCAP Analyzer
59. DNS DGA Detector
60. Linux Process Tree Logger
61. auditd Log Parser
62. SSH Brute-Force Detection Daemon
63. SSH Honeypot Logger
64. HTTP Honeypot Logger
65. NetFlow/IPFIX Analyzer
66. TLS Configuration Auditor
67. Certificate Transparency Monitor
68. Firewall Rule Auditor
69. WiFi Deauth Detector
70. ARP Spoofing Detector
71. Rogue DHCP Detector
72. Email Phishing Detector (NLP)
73. File Quarantine Service
74. Phishing URL ML Detector
75. Login Anomaly Detector

### LEVEL 3 - ADVANCED (76-100)

76. Mini SIEM Platform
77. Lightweight EDR Agent
78. Real-Time FIM (inotify)
79. Static Malware Analyzer
80. Office Macro Risk Analyzer
81. Forensics Timeline Builder
82. Memory Dump IOC Extractor
83. Disk Image Hash & Chain-of-Custody
84. Secrets Scanner
85. Dependency Vulnerability Checker
86. SBOM Generator
87. Dockerfile Linter & CIS Checker
88. Container Image Scanner
89. Kubernetes RBAC Auditor
90. Terraform Security Scanner
91. Cloud IAM Policy Analyzer
92. S3 Misconfiguration Detector
93. Zero Trust Network Gateway
94. Supply Chain Verifier (SLSA/Sigstore)
95. DLP Engine
96. Behavioral Authentication PoC
97. Encrypted Messaging Library (Double Ratchet)
98. Network ML Anomaly Detector
99. Threat Hunting Toolkit
100. GDPR/KVKK Compliance Auditor

---

## Execution Plan

- **Phase 1:** Build the full skeleton (all root files, .github/, docs/, parent pyproject.toml, three level folders with their READMEs, main README listing all 100 projects with links). Then show the tree and ask "Scaffold ready, shall I start projects 1-10?"
- **Phase 2:** On "continue", build projects in batches of 10. Full code + tests + README + pyproject.toml + threat model. After each batch, show summary and wait for "continue".
- **Phase 3:** After project 100, run final consistency pass.

If filter blocks you: STOP, report exactly where, propose alternative, wait for approval.
