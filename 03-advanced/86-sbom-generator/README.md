# Project 86 — SBOM Generator

> Generates CycloneDX 1.4 and SPDX 2.3 Software Bills of Materials from Python, Node.js, and Go dependency manifests.

## What Attack Does This Defend Against? (MITRE ATT&CK)

| Technique | ID | Description |
|---|---|---|
| Supply Chain Compromise | T1195.001 | Provides full dependency inventory for audit |
| Exploit Public-Facing Application | T1190 | Enables rapid CVE lookup per component |

## Features

- Parses requirements.txt, package.json, go.mod, pyproject.toml
- Outputs CycloneDX 1.4 JSON (industry standard)
- Outputs SPDX 2.3 JSON (government/compliance standard)
- Package URL (purl) generation per component
- License tracking
- SBOM summary command

## Install & Run on Kali

```bash
cd 03-advanced/86-sbom-generator
pip install -e .
sbom-generator generate requirements.txt -o sbom.json
sbom-generator generate package.json --format spdx -o sbom.spdx.json
sbom-generator summary sbom.json
```

## Testing

```bash
pytest tests/ -v --cov=project_86
```
