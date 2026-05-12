"""Tests for Dependency Vulnerability Checker core."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from project_85.core import (
    Dependency,
    _extract_fixed_version,
    _parse_severity,
    detect_and_parse,
    parse_go_mod,
    parse_package_json,
    parse_requirements_txt,
    query_osv_batch,
    query_osv_single,
)


class TestParseRequirementsTxt:
    def test_pinned_version(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.28.0\nflask>=2.0.0\nclick~=8.1.3\n")
        deps = parse_requirements_txt(f)
        names = [d.name for d in deps]
        assert "requests" in names
        assert "flask" in names
        assert "click" in names
        assert all(d.ecosystem == "PyPI" for d in deps)

    def test_skips_comments(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("# comment\nrequests==2.28.0\n-r other.txt\n")
        deps = parse_requirements_txt(f)
        assert len(deps) == 1

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("")
        assert parse_requirements_txt(f) == []


class TestParsePackageJson:
    def test_parses_deps(self, tmp_path: Path) -> None:
        f = tmp_path / "package.json"
        f.write_text(json.dumps({
            "dependencies": {"express": "^4.18.2", "lodash": "~4.17.21"},
            "devDependencies": {"jest": "^29.0.0"},
        }))
        deps = parse_package_json(f)
        names = [d.name for d in deps]
        assert "express" in names
        assert "lodash" in names
        assert "jest" in names
        assert all(d.ecosystem == "npm" for d in deps)

    def test_strips_semver_prefix(self, tmp_path: Path) -> None:
        f = tmp_path / "package.json"
        f.write_text(json.dumps({"dependencies": {"react": "^18.2.0"}}))
        deps = parse_package_json(f)
        assert deps[0].version == "18.2.0"


class TestParseGoMod:
    def test_parses_require_block(self, tmp_path: Path) -> None:
        f = tmp_path / "go.mod"
        f.write_text(
            "module example.com/app\ngo 1.21\n\n"
            "require (\n"
            "    github.com/gorilla/mux v1.8.0\n"
            "    golang.org/x/crypto v0.14.0\n"
            ")\n"
        )
        deps = parse_go_mod(f)
        names = [d.name for d in deps]
        assert "github.com/gorilla/mux" in names
        assert all(d.ecosystem == "Go" for d in deps)


class TestDetectAndParse:
    def test_requirements_txt(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.28.0\n")
        deps = detect_and_parse(f)
        assert deps[0].ecosystem == "PyPI"

    def test_package_json(self, tmp_path: Path) -> None:
        f = tmp_path / "package.json"
        f.write_text(json.dumps({"dependencies": {"express": "^4.0.0"}}))
        deps = detect_and_parse(f)
        assert deps[0].ecosystem == "npm"

    def test_unknown_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "Pipfile"
        f.write_text("[packages]\nrequests = '*'\n")
        with pytest.raises(ValueError, match="Unsupported"):
            detect_and_parse(f)


class TestParseSeverity:
    def test_critical_from_db_specific(self) -> None:
        vuln = {"database_specific": {"severity": "CRITICAL"}, "severity": []}
        label, score = _parse_severity(vuln)
        assert label == "CRITICAL"

    def test_unknown_default(self) -> None:
        vuln = {}
        label, score = _parse_severity(vuln)
        assert label == "UNKNOWN"


class TestExtractFixedVersion:
    def test_extracts_fixed(self) -> None:
        vuln = {"affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.29.0"}]}]}]}
        assert _extract_fixed_version(vuln) == "2.29.0"

    def test_no_fixed(self) -> None:
        vuln = {"affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}]}
        assert _extract_fixed_version(vuln) == ""


class TestQueryOSV:
    def _mock_response(self, data: dict) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    def test_query_single_no_vulns(self) -> None:
        dep = Dependency("safe-package", "1.0.0", "PyPI")
        with patch("urllib.request.urlopen", return_value=self._mock_response({"vulns": []})):
            result = query_osv_single(dep)
        assert result.vulnerabilities == []
        assert result.error == ""

    def test_query_single_with_vuln(self) -> None:
        dep = Dependency("requests", "2.0.0", "PyPI")
        osv_data = {"vulns": [{"id": "PYSEC-2023-001", "summary": "Test vuln", "severity": [],
                                "affected": [], "references": [], "database_specific": {"severity": "HIGH"}}]}
        with patch("urllib.request.urlopen", return_value=self._mock_response(osv_data)):
            result = query_osv_single(dep)
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].vuln_id == "PYSEC-2023-001"

    def test_query_single_network_error(self) -> None:
        import urllib.error
        dep = Dependency("pkg", "1.0.0", "PyPI")
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")):
            result = query_osv_single(dep)
        assert result.error != ""
        assert result.vulnerabilities == []

    def test_query_batch(self) -> None:
        deps = [Dependency("pkg1", "1.0.0", "PyPI"), Dependency("pkg2", "2.0.0", "PyPI")]
        batch_data = {"results": [{"vulns": []}, {"vulns": []}]}
        with patch("urllib.request.urlopen", return_value=self._mock_response(batch_data)):
            results = query_osv_batch(deps)
        assert len(results) == 2
