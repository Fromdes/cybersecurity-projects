# Threat Model — SBOM Generator

## MITRE Coverage
T1195.001, T1190

## Limitations
- Only direct dependencies from manifest files; transitive deps not resolved.
- License information requires pip metadata lookup (not yet implemented).
- For production, pair with Syft or CycloneDX CLI for deeper analysis.
