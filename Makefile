.PHONY: all lint test security clean help

PYTHON := python3
PROJECTS := $(wildcard 01-beginner/*/.) $(wildcard 02-intermediate/*/.) $(wildcard 03-advanced/*./)

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  lint      Run ruff + mypy on all projects"
	@echo "  test      Run pytest with coverage on all projects"
	@echo "  security  Run bandit on all projects"
	@echo "  all       Run lint, test, and security"
	@echo "  clean     Remove build artifacts and caches"

all: lint test security

lint:
	@echo "==> ruff check"
	ruff check .
	@echo "==> mypy"
	@for dir in $(PROJECTS); do \
		if [ -d "$$dir/src" ]; then \
			echo "  mypy $$dir"; \
			mypy --strict "$$dir/src" || exit 1; \
		fi \
	done

test:
	@echo "==> pytest"
	@for dir in $(PROJECTS); do \
		if [ -d "$$dir/tests" ]; then \
			echo "  pytest $$dir"; \
			(cd "$$dir" && $(PYTHON) -m pytest --cov=src --cov-fail-under=80 -q) || exit 1; \
		fi \
	done

security:
	@echo "==> bandit"
	@for dir in $(PROJECTS); do \
		if [ -d "$$dir/src" ]; then \
			echo "  bandit $$dir"; \
			bandit -r "$$dir/src" -ll || exit 1; \
		fi \
	done

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.coverage" -delete 2>/dev/null || true
	find . -name "coverage.xml" -delete 2>/dev/null || true
	@echo "Clean complete."
