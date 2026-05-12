# Project 82 — Memory Dump IOC Extractor

> Scans raw memory dumps and binary files for indicators of compromise (IPs, domains, URLs, file hashes, registry keys, Windows paths) using streaming regex extraction.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Command and Control | T1071 | Extracts C2 IPs, domains, URLs from memory |
| Indicator Removal | T1070 | Recovers artifacts from in-memory only malware |
| Exfiltration | T1041 | Finds exfil destination IPs/URLs |
| Defense Evasion: Memory | T1055 | Reveals injected code network artifacts |

## Features

- 10 IOC types: IPv4, IPv6, URL, domain, email, MD5, SHA1, SHA256, Windows path, registry key
- Private/loopback IP filtering
- Streaming 1MB chunk reads — handles multi-GB dump files
- SHA-256 of analyzed file for chain of custody
- JSON report output

## Tech Stack

- Python 3.11+, re, hashlib, click (no external IOC libs)

## Architecture

```
Memory Dump File
    │
    ▼ (1MB chunks with 256-byte overlap)
IOCExtractor.extract_from_bytes()
    │
    ├── IPv4 / IPv6 regex ──► filter private IPs
    ├── URL / domain regex
    ├── Email regex
    ├── MD5 / SHA1 / SHA256 regex ──► filter low-entropy sequences
    ├── Windows path regex
    └── Registry key regex
         │
         ▼
ExtractionResult ──► JSON report
```

## Threat Model (STRIDE)

| STRIDE | Risk | Mitigation |
|---|---|---|
| Tampering | Dump file modified before analysis | SHA-256 checksum in report |
| Info Disclosure | Sensitive memory content in output | Restrict report file permissions |
| DoS | Multi-GB dump exhausts RAM | Streaming chunked read; size limit |

## Install & Run on Kali

```bash
cd 03-advanced/82-memory-dump-ioc
pip install -e .
memory-ioc extract /mnt/forensics/memory.dmp -o report.json
memory-ioc scan-text /var/log/app.log -o iocs.json
memory-ioc extract /mnt/forensics/memory.dmp --types ipv4 url domain
```

## Privileges

No special privileges needed (read access to dump file required).

## Example Output

```
SHA256: 3a4b5c...
Total IOCs extracted: 47

[IPV4] (3)
  8.8.4.4
  185.220.101.5
  45.33.32.156

[URL] (2)
  http://c2.evil.com/beacon
  https://update.malware.xyz/payload.exe
```

## Testing

```bash
pytest tests/ -v --cov=project_82
```

## What You'll Learn

- Binary pattern matching with compiled regex
- Memory forensics artifact extraction
- Streaming chunked file processing
- IOC filtering and deduplication

## References

- [MITRE ATT&CK C2](https://attack.mitre.org/tactics/TA0011/)
- [MemProcFS / Volatility for advanced memory analysis](https://github.com/ufrisk/MemProcFS)
