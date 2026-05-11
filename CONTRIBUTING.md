# Contributing

Thank you for your interest in contributing to this defensive cybersecurity portfolio.

## Ground Rules

1. **Defensive only.** No offensive tools, exploits, or attack-enabling code. See `CLAUDE.md` for the full list of prohibited and allowed categories.
2. **Python 3.11+** exclusively. No other languages.
3. All code must pass `make lint test security` with zero errors before a PR is opened.

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/cybersecurity-projects.git
cd cybersecurity-projects
pip install -r requirements-dev.txt
```

## Workflow

1. Fork the repository and create a branch: `git checkout -b feat/project-NN-short-name`
2. Write code + tests + README following the per-project template in `CLAUDE.md`.
3. Run `make all` from the project directory — all checks must pass.
4. Open a PR using the pull request template.

## Code Standards

| Check | Command | Requirement |
|-------|---------|-------------|
| Lint | `ruff check .` | Zero errors |
| Type check | `mypy --strict src/` | Zero errors |
| Security | `bandit -r src/` | No medium/high findings |
| Tests | `pytest --cov=src --cov-fail-under=80` | ≥ 80% coverage |

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(project-02): add SHA-3 support to file hash calculator
fix(project-07): handle HIBP API rate limit with exponential backoff
docs(project-14): add STRIDE threat model table
```

## Adding a New Project

Each project directory must contain:

```
NN-name/
├── README.md           (use the template in CLAUDE.md)
├── pyproject.toml
├── requirements.txt
├── src/project_NN/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   └── core.py
├── tests/
│   ├── test_core.py
│   └── test_cli.py
├── docs/
│   ├── architecture.md
│   └── threat-model.md
└── examples/
```

## Questions

Open a GitHub Discussion or an issue using the `question` label.
