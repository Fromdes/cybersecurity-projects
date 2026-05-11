# Cybersecurity Glossary

Terms used across this project, explained in plain language.

---

## A

**ABAC** — Attribute-Based Access Control. Access decisions based on user/resource/environment attributes, more flexible than RBAC.

**ARP** — Address Resolution Protocol. Maps IP addresses to MAC addresses on a local network. Vulnerable to spoofing (ARP poisoning).

**ASN** — Autonomous System Number. A unique identifier for a network on the internet (e.g., AS15169 = Google).

---

## B

**Bandit** — A Python AST-based security linter that finds common security issues.

**Blue Team** — The defensive side of cybersecurity: monitoring, detection, response, hardening.

**Brute Force** — Systematically trying all possible passwords or keys. Mitigated by rate limiting, lockout, and strong password policies.

---

## C

**CTI** — Cyber Threat Intelligence. Information about adversaries, their TTPs, and IOCs.

**CVE** — Common Vulnerabilities and Exposures. A catalog of publicly disclosed security vulnerabilities.

**CVSS** — Common Vulnerability Scoring System. A 0–10 score for vulnerability severity.

---

## D

**DKIM** — DomainKeys Identified Mail. Email authentication using public-key cryptography to verify the sender domain.

**DMARC** — Domain-based Message Authentication, Reporting & Conformance. Policy framework combining SPF and DKIM.

**DGA** — Domain Generation Algorithm. Malware technique to generate many C2 domain names, evading blocklists.

**DLP** — Data Loss Prevention. Controls to detect and block unauthorized data exfiltration.

---

## E

**EDR** — Endpoint Detection & Response. Security software that monitors endpoint activity for malicious behavior.

---

## F

**FIM** — File Integrity Monitoring. Detecting unauthorized changes to files (e.g., config files, binaries).

**FIDO2** — Fast Identity Online 2. Passwordless authentication standard (WebAuthn + CTAP).

---

## H

**HIBP** — Have I Been Pwned. A service for checking whether credentials appear in known data breaches.

**HMAC** — Hash-based Message Authentication Code. Combines a cryptographic hash with a secret key to verify message integrity.

**Honeypot** — A decoy system designed to attract and log attacker activity without risk to real systems.

---

## I

**IOC** — Indicator of Compromise. Evidence of a security breach: IP addresses, file hashes, domain names, etc.

**inotify** — A Linux kernel subsystem for monitoring filesystem events in real time.

---

## J

**JWT** — JSON Web Token. A compact, signed (and optionally encrypted) token for conveying claims between parties.

---

## M

**MITRE ATT&CK** — A knowledge base of adversary tactics, techniques, and procedures (TTPs) based on real-world observations.

**MFA** — Multi-Factor Authentication. Requiring two or more verification factors (something you know, have, or are).

---

## O

**OSINT** — Open Source Intelligence. Information gathered from publicly available sources.

---

## P

**PCAP** — Packet Capture. A file format for storing captured network traffic (used by Wireshark, tcpdump).

**PBKDF2** — Password-Based Key Derivation Function 2. A key stretching algorithm for hashing passwords.

---

## R

**RBAC** — Role-Based Access Control. Access decisions based on a user's assigned role.

**Red Team** — Simulates attackers to test an organization's defenses. This project is **not** a red team tool.

---

## S

**SBOM** — Software Bill of Materials. A list of all components, libraries, and dependencies in a software product.

**SIEM** — Security Information and Event Management. Aggregates and correlates security events from multiple sources.

**SLSA** — Supply chain Levels for Software Artifacts. A framework for improving supply chain integrity.

**SPF** — Sender Policy Framework. Specifies which mail servers are authorized to send email for a domain.

**STIX** — Structured Threat Information Expression. A JSON-based language for describing CTI.

**STRIDE** — A threat modeling framework: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.

---

## T

**TAXII** — Trusted Automated eXchange of Intelligence Information. A protocol for sharing CTI over HTTPS.

**TOTP** — Time-based One-Time Password. Generates a short-lived code based on the current time and a shared secret (RFC 6238).

**TTP** — Tactics, Techniques, and Procedures. Describes how an adversary operates.

---

## Y

**YARA** — A pattern-matching tool used to identify and classify malware based on rules.

---

## Z

**Zero Trust** — A security model that assumes no user or system is inherently trusted, requiring continuous verification.
