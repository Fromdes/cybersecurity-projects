# Level 1 — Beginner Projects (01–35)

These 35 projects cover the foundational concepts of defensive cybersecurity. Each one is a self-contained CLI tool you can run immediately on Kali Linux.

**Skills you'll build**: cryptography basics, secure hashing, password security, authentication, TLS/PKI inspection, log parsing, file integrity monitoring, and basic host auditing.

---

## Projects

| # | Name | MITRE ATT&CK | Status |
|---|------|-------------|--------|
| [01](01-caesar-vigenere-cipher/) | Caesar & Vigenere Cipher Toolkit | T1027 | Pending |
| [02](02-file-hash-calculator/) | File Hash Calculator | T1027, T1553 | Pending |
| [03](03-file-integrity-verifier/) | File Integrity Verifier | T1565 | Pending |
| [04](04-password-strength-analyzer/) | Password Strength Analyzer | T1110 | Pending |
| [05](05-secure-password-generator/) | Secure Password Generator | T1110 | Pending |
| [06](06-diceware-passphrase-generator/) | Diceware Passphrase Generator | T1110 | Pending |
| [07](07-hibp-client/) | Have-I-Been-Pwned Client | T1586 | Pending |
| [08](08-aes256-gcm-encryptor/) | AES-256-GCM File Encryptor | T1022 | Pending |
| [09](09-rsa-key-pair-generator/) | RSA Key Pair Generator & File Signer | T1553 | Pending |
| [10](10-x509-certificate-inspector/) | X.509 Certificate Inspector | T1587.003 | Pending |
| [11](11-totp-hotp-authenticator/) | TOTP/HOTP Authenticator | T1078 | Pending |
| [12](12-qr-totp-provisioner/) | QR Code TOTP Provisioner | T1078 | Pending |
| [13](13-hmac-authenticator/) | HMAC Message Authenticator | T1565 | Pending |
| [14](14-argon2id-password-hasher/) | Argon2id/PBKDF2 Password Hasher | T1110 | Pending |
| [15](15-secure-token-generator/) | Secure Token Generator | T1528 | Pending |
| [16](16-encoding-toolkit/) | Encoding Toolkit | T1027 | Pending |
| [17](17-tls-handshake-inspector/) | TLS Handshake Inspector | T1587.003 | Pending |
| [18](18-dns-lookup-tool/) | DNS Lookup & Reverse DNS Tool | T1071.004 | Pending |
| [19](19-ip-geolocation-asn/) | IP Geolocation & ASN Lookup | T1590 | Pending |
| [20](20-whois-lookup/) | WHOIS Lookup Wrapper | T1590 | Pending |
| [21](21-url-parser-validator/) | URL Parser & Validator | T1566 | Pending |
| [22](22-phishing-url-detector/) | Phishing URL Heuristic Detector | T1566.002 | Pending |
| [23](23-email-header-analyzer/) | Email Header Analyzer (SPF/DKIM/DMARC) | T1566.001 | Pending |
| [24](24-file-type-identifier/) | File Type Identifier | T1036 | Pending |
| [25](25-steganography-detector/) | Steganography Detector | T1027.003 | Pending |
| [26](26-access-log-parser/) | Apache/Nginx Access Log Parser | T1190 | Pending |
| [27](27-failed-login-counter/) | Failed Login Counter | T1110 | Pending |
| [28](28-file-integrity-monitor/) | File Integrity Monitor (polling) | T1565 | Pending |
| [29](29-directory-permission-auditor/) | Directory Permission Auditor | T1222 | Pending |
| [30](30-suspicious-process-lister/) | Suspicious Process Lister | T1057 | Pending |
| [31](31-listening-port-auditor/) | Listening Port Auditor | T1049 | Pending |
| [32](32-hosts-file-tamper-detector/) | Hosts File Tamper Detector | T1565.001 | Pending |
| [33](33-browser-history-cleaner/) | Browser History Privacy Cleaner | T1552 | Pending |
| [34](34-encrypted-notes-cli/) | Encrypted Notes CLI | T1022 | Pending |
| [35](35-encrypted-backup-tool/) | Encrypted Backup Tool | T1022, T1565 | Pending |

---

## Prerequisites

```bash
python3 --version  # 3.11+
pip install -r requirements-dev.txt  # from repo root
```

Each project has its own `requirements.txt`. Navigate into the project directory and follow its README.
