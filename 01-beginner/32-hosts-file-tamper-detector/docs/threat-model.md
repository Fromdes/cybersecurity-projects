# Threat Model — Project 32: Hosts File Tamper Detector

## Assets
- DNS resolution integrity for the local machine
- Authenticity of connections to high-value web services

## Threat Actors
- Malware that gains write access to /etc/hosts (requires root or sudo)
- Insider with root access who redirects a domain for credential theft
- Supply-chain attack that modifies hosts during software installation

## STRIDE Analysis
| Threat | Example | Mitigation |
|---|---|---|
| Spoofing | paypal.com → attacker IP for credential phishing | Suspicious redirect heuristic; alert on non-loopback IPs for known domains |
| Tampering | Any byte change to /etc/hosts | SHA-256 hash comparison; alert on hash change |
| Repudiation | Malware reverts changes after exfiltration | Store baseline with timestamp; audit trail |
| Info Disclosure | Local intranet hostnames leaked via hosts file | Restrict hosts file read permissions |
| Denial of Service | Critical service names mapped to 0.0.0.0 | Detect entries pointing to 0.0.0.0 for production FQDNs |

## Threat Hunting Use Cases
- Run check on every login via PAM module or cron
- Alert when /etc/hosts inode mtime changes (pair with Project 28 or 78)
- Cross-reference newly added IPs against threat intel feeds (pair with Project 56)
- Detect persistence via hosts overriding security vendor update domains
