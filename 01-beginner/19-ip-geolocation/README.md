# Project 19 - IP Geolocation & ASN Lookup
> Identify the geographic location, ISP, ASN, and proxy/hosting status of IP addresses to aid threat analysis.

## What Attack Does This Defend Against? (MITRE ATT&CK IDs)
| Technique | ID | Description |
|---|---|---|
| Proxy | T1090 | Attackers route traffic through proxies/VPNs |
| Acquire Infrastructure | T1583 | Identify hosting/cloud IPs used as C2 |
| External Remote Services | T1133 | Detect logins from unexpected geographies |

## Features
- **Single IP lookup**: country, city, region, coordinates, ISP, org, ASN
- **Proxy/hosting flags**: detect VPN, Tor exit nodes, datacenter IPs
- **Bulk lookup**: process a list of IPs from a file
- **JSON output**: pipeline-friendly structured output
- **"me" shortcut**: look up your own public IP

## Tech Stack
- Python 3.11+, `requests>=2.31`, ip-api.com free tier (no API key required)

## Architecture
```
CLI (cli.py)
  lookup_ip(ip) → GeoResult
    └─ requests.get(ip-api.com/json/{ip})
    └─ _parse_result(data) → GeoResult
```

## Threat Model (STRIDE)
| Category | Threat | Mitigation |
|---|---|---|
| Spoofing | IP spoofing hides origin | Combine with TCP session data |
| Info Disclosure | API call leaks investigated IPs | ip-api is a third-party; consider local MaxMind DB |
| Repudiation | Geolocation data inaccurate | Note: geo data is best-effort, not forensic-grade |

## Install & Run on Kali
```bash
cd 01-beginner/19-ip-geolocation
pip install -e .
ip-geo 8.8.8.8
ip-geo 1.1.1.1 --json
ip-geo me
ip-geo --file ips.txt
```

## Privileges
No root required. Requires internet access to ip-api.com.

## Example Output
```
IP            : 8.8.8.8 [HOSTING/DC]
Country       : United States (US)
Region / City : California, Mountain View
Coordinates   : 37.386, -122.0838
ISP           : Google LLC
Organisation  : AS15169 Google LLC
ASN           : AS15169 Google LLC
Timezone      : America/Los_Angeles
```

## Testing
```bash
pip install -r requirements.txt
pytest --cov=project_19 --cov-report=term-missing
```

## What You'll Learn
- ASN (Autonomous System Numbers) and IP ownership hierarchy
- REST API consumption with `requests` and error handling
- Why datacenter/proxy IPs are suspicious in authentication logs
- Bulk IP enrichment patterns for SOC workflows

## References
- [MITRE ATT&CK T1090 – Proxy](https://attack.mitre.org/techniques/T1090/)
- [ip-api.com documentation](https://ip-api.com/docs)
- [BGP/ASN explained (RIPE NCC)](https://www.ripe.net/about-us/press-centre/understanding-ip-addressing)
