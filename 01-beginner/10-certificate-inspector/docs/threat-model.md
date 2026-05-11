# Threat Model — Project 10: X.509 Certificate Inspector

## Asset

TLS certificate validity and configuration for services under monitoring.

## STRIDE

| Threat | Rating | Notes |
|---|---|---|
| Spoofing | Critical | Self-signed / wrong-CN certs allow MITM identity spoofing |
| **Tampering** | **High** | Expired/weak cert enables active MITM to modify traffic |
| Repudiation | Low | Cert inspection is read-only, no actions taken |
| **Info Disclosure** | **High** | Weak keys (RSA-512) can be factored; MITM reads plaintext |
| DoS | Medium | Expired cert causes browsers to block the site entirely |
| Elevation of Privilege | Low | Inspection-only; no certificate installation |

## Monitoring Strategy

Run `cert-inspect host <your-domain> --json` in a cron job and feed the output
to your SIEM (Project 76). Alert if `expiry_status` is `warning` or `critical`,
or if `warnings` is non-empty. This gives 30 days of notice before expiry.
