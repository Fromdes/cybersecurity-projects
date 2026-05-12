# Threat Model — Dockerfile Linter

## MITRE Coverage
T1611, T1195.001, T1552, T1105, T1548

## CIS Docker Benchmark Coverage
- 4.1 Non-root user
- 4.2 Specific image tags
- 4.6 HEALTHCHECK
- 4.10 No secrets in ENV

## Limitations
- Does not analyze runtime docker-compose.yml overrides.
- Multi-stage builds: USER in builder stage does not carry over to final stage.
