# Threat Model — Project 18: DNS Lookup & Reverse DNS Tool

## Assets
- DNS records for monitored domains
- Reverse DNS mappings for known IP ranges

## Threat Actors
- DNS hijackers modifying A/NS records
- DGA-based malware communicating via DNS

## STRIDE Analysis
| Threat | Example | Mitigation |
|---|---|---|
| Spoofing | Cache poisoning → wrong A record returned | Query multiple resolvers; compare results |
| Tampering | Attacker changes NS records to rogue DNS | Schedule periodic NS record audits |
| Info Disclosure | TXT/SPF records expose internal mail setup | Audit TXT records for overly permissive SPF |
| Denial of Service | DNS amplification attack (UDP) | Out of scope; use rate-limiting at firewall |

## Threat Hunting Use Cases
- Query TXT records for unexpected SPF/DMARC changes
- Monitor NS records weekly for domain hijacking
- Reverse-lookup IP ranges to identify rogue PTR entries
- Compare SOA serial numbers over time for unauthorised zone changes
