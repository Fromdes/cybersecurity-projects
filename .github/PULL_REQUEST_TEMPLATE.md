## Summary

<!-- What does this PR do? Link the issue if applicable. Closes #NNN -->

## Type of change

- [ ] New project (project NN — name)
- [ ] Bug fix (existing project)
- [ ] Enhancement (existing project)
- [ ] Documentation
- [ ] CI/Infrastructure

## Defensive purpose

<!-- What attack does this defend against? MITRE ATT&CK IDs? -->

## Checklist

- [ ] `make lint` passes with zero errors (ruff + mypy --strict)
- [ ] `make test` passes with ≥ 80% coverage
- [ ] `make security` passes (no bandit medium/high findings)
- [ ] README.md updated with MITRE ATT&CK IDs, install instructions, and example output
- [ ] `docs/threat-model.md` present with STRIDE table
- [ ] No offensive code, credentials, or hardcoded secrets
- [ ] `pyproject.toml` and `requirements.txt` present and pinned
- [ ] Google-style docstrings on all public functions/classes
- [ ] Functions ≤ 30 lines, modules ≤ 300 lines
