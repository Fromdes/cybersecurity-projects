# Threat Model — Project 19: IP Geolocation & ASN Lookup

## Assets
- Enriched threat intelligence about attacker IP addresses
- Authentication log context (unexpected geographies)

## Threat Actors
- Attackers routing through proxies/VPNs to hide origin
- Botnets using residential IPs to blend in

## STRIDE Analysis
| Threat | Example | Mitigation |
|---|---|---|
| Spoofing | IP spoofing hides true origin | Geo data supplements; always combine with session data |
| Info Disclosure | Sending IPs to ip-api.com (3rd party) | Consider local GeoIP2 DB (MaxMind) for sensitive IPs |
| Repudiation | Geolocation data wrong/outdated | Document as best-effort; not forensic-grade |
| Tampering | ISP/ASN data changes after registration | Re-query fresh data, do not cache long-term |

## Operational Use Cases
- Flag authentication attempts from unexpected countries
- Identify datacenter/hosting IPs in login logs (likely automated)
- Enrich IOC reports with ASN information
- Detect proxy/VPN usage in high-risk transactions
