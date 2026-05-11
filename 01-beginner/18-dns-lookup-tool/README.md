# Project 18 - DNS Lookup & Reverse DNS Tool
> Query DNS records (A, MX, TXT, NS, SOA, CNAME) and reverse-resolve IPs to detect DNS hijacking and misconfigurations.

## What Attack Does This Defend Against? (MITRE ATT&CK IDs)
| Technique | ID | Description |
|---|---|---|
| DNS | T1071.004 | Attackers use DNS for C2 communication |
| Dynamic Resolution | T1568 | DGA domains change frequently; track NS/SOA |
| DNS Hijacking | T1584.002 | Detect unexpected NS/A record changes |

## Features
- **Record types**: A, AAAA, MX, TXT, NS, CNAME, SOA, PTR
- **Reverse DNS**: IP → hostname via PTR records
- **Configurable resolver timeout**: avoids hanging on unresponsive servers
- **Structured output**: name, type, TTL, value columns
- **Offline-safe**: only `dnspython` as runtime dependency

## Tech Stack
- Python 3.11+, `dnspython>=2.6`

## Architecture
```
CLI (cli.py)
  lookup(hostname, RecordType) → list[DNSRecord]
  reverse_lookup(ip)           → list[DNSRecord]
    └─ dns.resolver.Resolver
    └─ dns.reversename.from_address()
```

## Threat Model (STRIDE)
| Category | Threat | Mitigation |
|---|---|---|
| Spoofing | DNS cache poisoning → wrong A record | Compare results against multiple resolvers |
| Tampering | Attacker modifies NS records | Monitor NS records for unexpected changes |
| Info Disclosure | TXT records expose internal info | Audit TXT/SPF records regularly |

## Install & Run on Kali
```bash
cd 01-beginner/18-dns-lookup-tool
pip install -e .
dns-lookup lookup example.com --type A
dns-lookup lookup example.com --type MX
dns-lookup lookup example.com --type TXT
dns-lookup reverse 8.8.8.8
```

## Privileges
No root required.

## Example Output
```
example.com.                             A          300s  93.184.216.34
example.com.                             MX         3600s  0 .
8.8.8.8.in-addr.arpa.                   PTR        21599s  dns.google.
```

## Testing
```bash
pip install -r requirements.txt
pytest --cov=project_18 --cov-report=term-missing
```

## What You'll Learn
- DNS record types and what each reveals about infrastructure
- `dnspython` resolver API and reverse name utilities
- How PTR records work (in-addr.arpa, ip6.arpa)
- DNS-based threat hunting (suspicious TXT, rogue NS)

## References
- [MITRE ATT&CK T1071.004 – DNS](https://attack.mitre.org/techniques/T1071/004/)
- [dnspython documentation](https://dnspython.readthedocs.io/)
- [RFC 1035 – Domain Names](https://www.rfc-editor.org/rfc/rfc1035)
