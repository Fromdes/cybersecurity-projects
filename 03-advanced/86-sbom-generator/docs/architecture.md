# Architecture — SBOM Generator

## Pipeline

manifest → `detect_and_parse()` → `Component[]` → `SBOMDocument` → CycloneDX / SPDX JSON

## Formats

- **CycloneDX 1.4**: `bomFormat`, `specVersion`, `components[]` with purl.
- **SPDX 2.3**: `spdxVersion`, `packages[]` with SPDXID and license fields.

Both formats include serial number (UUID) and creation timestamp for traceability.
