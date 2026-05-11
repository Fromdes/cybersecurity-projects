# Level 2 — Intermediate Projects (36–75)

These 40 projects move from standalone CLI tools to detection daemons, auth frameworks, threat-intel pipelines, and network monitors. Many run continuously as services.

**Skills you'll build**: JWT/OAuth2/FIDO2 authentication, web security headers, rate limiting, YARA/STIX/TAXII, PCAP analysis, SSH and HTTP honeypots, TLS auditing, WiFi/ARP/DHCP attack detection, and ML-based phishing detection.

---

## Projects

| # | Name | MITRE ATT&CK | Status |
|---|------|-------------|--------|
| [36](36-personal-password-vault/) | Personal Password Vault | T1110, T1555 | Pending |
| [37](37-jwt-validator/) | JWT Validator & Inspector | T1528 | Pending |
| [38](38-oauth2-pkce-client/) | OAuth2 PKCE Client | T1528 | Pending |
| [39](39-rbac-engine/) | RBAC Engine | T1078 | Pending |
| [40](40-abac-policy-engine/) | ABAC Policy Engine | T1078 | Pending |
| [41](41-session-manager/) | Session Manager Service | T1550 | Pending |
| [42](42-webauthn-fido2-verifier/) | WebAuthn/FIDO2 Verifier | T1078 | Pending |
| [43](43-rate-limiter/) | Rate Limiter | T1110, T1499 | Pending |
| [44](44-input-sanitization-library/) | Input Sanitization Library | T1190 | Pending |
| [45](45-output-encoder/) | Output Encoder | T1059 | Pending |
| [46](46-csp-header-builder/) | CSP Header Builder & Reporter | T1059.007 | Pending |
| [47](47-csrf-token-service/) | CSRF Token Service | T1185 | Pending |
| [48](48-secure-file-upload/) | Secure File Upload Service | T1190 | Pending |
| [49](49-secure-rest-api/) | Secure REST API Template | T1190 | Pending |
| [50](50-audit-log-system/) | Audit Log System | T1562 | Pending |
| [51](51-structured-logger/) | Centralized Structured Logger | T1562.002 | Pending |
| [52](52-nmap-result-parser/) | Nmap Result Parser & Diff | T1595 | Pending |
| [53](53-port-scan-detector/) | Port Scan Detection from Logs | T1046 | Pending |
| [54](54-snort-suricata-rule-generator/) | Snort/Suricata Rule Generator | T1190 | Pending |
| [55](55-yara-rule-engine/) | YARA Rule Engine Orchestrator | T1204 | Pending |
| [56](56-ioc-matcher/) | IOC Matcher | T1071 | Pending |
| [57](57-stix-taxii-feed-parser/) | STIX/TAXII Feed Parser | T1071 | Pending |
| [58](58-pcap-analyzer/) | PCAP Analyzer | T1040 | Pending |
| [59](59-dns-dga-detector/) | DNS DGA Detector | T1568.002 | Pending |
| [60](60-linux-process-tree-logger/) | Linux Process Tree Logger | T1057 | Pending |
| [61](61-auditd-log-parser/) | auditd Log Parser | T1562.012 | Pending |
| [62](62-ssh-bruteforce-detector/) | SSH Brute-Force Detection Daemon | T1110.003 | Pending |
| [63](63-ssh-honeypot-logger/) | SSH Honeypot Logger | T1110 | Pending |
| [64](64-http-honeypot-logger/) | HTTP Honeypot Logger | T1190 | Pending |
| [65](65-netflow-ipfix-analyzer/) | NetFlow/IPFIX Analyzer | T1071 | Pending |
| [66](66-tls-config-auditor/) | TLS Configuration Auditor | T1587.003 | Pending |
| [67](67-cert-transparency-monitor/) | Certificate Transparency Monitor | T1587.003 | Pending |
| [68](68-firewall-rule-auditor/) | Firewall Rule Auditor | T1562.004 | Pending |
| [69](69-wifi-deauth-detector/) | WiFi Deauth Detector | T1498 | Pending |
| [70](70-arp-spoofing-detector/) | ARP Spoofing Detector | T1557.002 | Pending |
| [71](71-rogue-dhcp-detector/) | Rogue DHCP Detector | T1557 | Pending |
| [72](72-email-phishing-detector/) | Email Phishing Detector (NLP) | T1566 | Pending |
| [73](73-file-quarantine-service/) | File Quarantine Service | T1204 | Pending |
| [74](74-phishing-url-ml-detector/) | Phishing URL ML Detector | T1566.002 | Pending |
| [75](75-login-anomaly-detector/) | Login Anomaly Detector | T1078 | Pending |

---

## Prerequisites

Complete Level 1 projects first to build your Python and defensive-security foundations.

```bash
python3 --version  # 3.11+
# Some projects need system libraries:
sudo apt install -y libpcap-dev yara tshark
```
