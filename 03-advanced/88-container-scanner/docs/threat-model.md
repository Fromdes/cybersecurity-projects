# Threat Model — Container Image Scanner

## MITRE Coverage
T1611, T1552, T1552.001

## Limitations
- Requires `docker save` tarball; does not pull from registry directly.
- File content scanning limited to filenames; no content inspection of layer files.
- For full vulnerability scanning, pair with Trivy or Grype.
