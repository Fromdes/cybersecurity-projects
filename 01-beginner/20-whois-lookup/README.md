# Project 20 - WHOIS Lookup Wrapper
> Query WHOIS registration data for domains and IPs to identify attacker-controlled infrastructure and suspicious registrations.

## What Attack Does This Defend Against? (MITRE ATT&CK IDs)
| Technique | ID | Description |
|---|---|---|
| Acquire Infrastructure – Domains | T1583.001 | Newly registered domains used for phishing/C2 |
| Compromise Infrastructure | T1584 | Identify legitimate domains being weaponised |
| Phishing – spearphishing link | T1566.002 | Typosquat domains have suspicious creation dates |

## Features
- **Domain WHOIS**: registrar, creation/expiry/update dates, nameservers, status, emails
- **Parsed output**: structured Python dataclass (not raw text)
- **JSON mode**: machine-readable for SIEM integration
- **DNSSEC field**: check if domain has DNSSEC enabled
- **Age detection**: compare creation date to flag newly-registered domains

## Tech Stack
- Python 3.11+, `python-whois>=0.9`

## Architecture
```
CLI (cli.py)
  lookup(query) → WhoisResult
    └─ whois.whois(query)
    └─ _parse(query, data) → WhoisResult
```

## Threat Model (STRIDE)
| Category | Threat | Mitigation |
|---|---|---|
| Spoofing | Domain impersonation / typosquatting | Compare registrar and creation date |
| Info Disclosure | Privacy-protected WHOIS hides registrant | Flag privacy-protected registrations |
| Repudiation | WHOIS data can be falsified | Cross-reference with certificate transparency |
| Tampering | NS record changes indicate hijacking | Monitor NS changes over time |

## Install & Run on Kali
```bash
cd 01-beginner/20-whois-lookup
pip install -e .
whois-lookup example.com
whois-lookup google.com --json
whois-lookup 8.8.8.8
```

## Privileges
No root required. Requires internet access to WHOIS servers.

## Example Output
```
Query         : example.com
Registrar     : IANA
Created       : 1995-08-14
Expires       : 2024-08-13
Updated       : 2023-08-14
Name Servers  : a.iana-servers.net, b.iana-servers.net
Status        : clientDeleteProhibited
Emails        : N/A
Country       : US
DNSSEC        : signedDelegation
```

## Testing
```bash
pip install -r requirements.txt
pytest --cov=project_20 --cov-report=term-missing
```

## What You'll Learn
- WHOIS protocol and why registration metadata matters for threat intel
- `python-whois` API and its quirks (list vs single date values)
- Domain age as a phishing indicator (newly-registered domains are suspicious)
- DNSSEC and domain status codes (clientDeleteProhibited, serverHold)

## References
- [MITRE ATT&CK T1583.001 – Acquire Domains](https://attack.mitre.org/techniques/T1583/001/)
- [ICANN WHOIS policy](https://www.icann.org/resources/pages/whois-2012-02-25-en)
- [python-whois documentation](https://pypi.org/project/python-whois/)
