# Threat Model — Project 20: WHOIS Lookup Wrapper

## Assets
- Domain registration metadata for threat investigation
- Infrastructure attribution (registrar, nameservers)

## Threat Actors
- Phishing operators using newly-registered lookalike domains
- Threat actors using privacy-protected WHOIS to hide identity

## STRIDE Analysis
| Threat | Example | Mitigation |
|---|---|---|
| Spoofing | Typosquat domain with similar registrar | Check creation_date; new domains (< 30 days) are high risk |
| Tampering | NS records changed after domain compromise | Monitor NS changes; alert on deviations |
| Info Disclosure | WHOIS data sent to registrar servers | Data is public by design; GDPR-protected in EU |
| Repudiation | Privacy protection hides registrant | Flag privacy-protected registrations in reports |

## Threat Hunting Use Cases
- Flag domains created within 30 days of a phishing campaign
- Identify domains sharing the same registrar/nameserver as known IOCs
- Detect domain status `serverHold` (domain suspended for abuse)
- Cross-reference WHOIS emails against known threat actor accounts
