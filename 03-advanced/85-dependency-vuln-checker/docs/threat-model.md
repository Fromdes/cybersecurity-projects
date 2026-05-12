# Threat Model — Dependency Vulnerability Checker

## MITRE Coverage
T1195.001, T1190

## Limitations

- Only checks packages listed in manifest files — transitive dependencies not yet resolved.
- OSV database may lag zero-days by days or weeks.
- Version range checks depend on accurate version pinning in manifests.

## Production Hardening

- Run in CI on every pull request with `--exit-code`.
- Pair with `pip-audit` or `npm audit` for complementary coverage.
- Review OSV advisories via https://osv.dev/list for new CVEs.
