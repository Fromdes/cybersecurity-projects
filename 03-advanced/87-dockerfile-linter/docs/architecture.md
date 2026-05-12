# Architecture — Dockerfile Linter

## Pipeline

`parse_dockerfile()` → `DockerfileInstruction[]` → each check function → `LintFinding[]` → sorted by severity

## Rules

Each check is a pure function `(list[DockerfileInstruction]) -> list[LintFinding]`. Adding new rules requires implementing the function and adding it to `ALL_CHECKS`.
