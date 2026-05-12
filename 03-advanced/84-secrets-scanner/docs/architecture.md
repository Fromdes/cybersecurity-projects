# Architecture — Secrets Scanner

## Rule Design

Each `SecretRule` is a frozen dataclass with a pre-compiled regex. Rules are applied in order; the first match on a line stops further checks (one finding per line to avoid noise).

## Allowlist Pipeline

Before applying rules, `_is_allowlisted()` checks the line for test/example/nosec markers. This runs first so no regex is evaluated against known-safe lines.

## Redaction

`_redact()` shows only the first and last 4 characters of a matched value in output, preventing secrets from leaking into scan reports shared in CI artifacts.
