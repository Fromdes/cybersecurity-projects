"""Tests for SBOM Generator core."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from project_86.core import (
    Component,
    SBOMDocument,
    _make_purl,
    detect_and_parse,
    parse_go_mod,
    parse_package_json,
    parse_requirements_txt,
)


class TestMakePurl:
    def test_pypi(self) -> None:
        assert _make_purl("PyPI", "requests", "2.28.0") == "pkg:pypi/requests@2.28.0"

    def test_npm(self) -> None:
        assert _make_purl("npm", "lodash", "4.17.21") == "pkg:npm/lodash@4.17.21"

    def test_go(self) -> None:
        assert _make_purl("Go", "github.com/gorilla/mux", "1.8.0") == "pkg:golang/github.com/gorilla/mux@1.8.0"


class TestParseRequirementsTxt:
    def test_pinned(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.28.0\nflask>=2.0.0\n")
        comps = parse_requirements_txt(f)
        assert len(comps) == 2
        names = [c.name for c in comps]
        assert "requests" in names

    def test_skips_comments(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("# comment\nrequests==2.28.0\n-r other.txt\n")
        comps = parse_requirements_txt(f)
        assert len(comps) == 1

    def test_purl_ecosystem(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("click==8.1.0\n")
        comps = parse_requirements_txt(f)
        assert comps[0].ecosystem == "PyPI"
        assert "pypi" in comps[0].purl


class TestParsePackageJson:
    def test_parses_deps(self, tmp_path: Path) -> None:
        f = tmp_path / "package.json"
        f.write_text(json.dumps({"dependencies": {"express": "^4.18.2"}}))
        comps = parse_package_json(f)
        assert len(comps) == 1
        assert comps[0].name == "express"
        assert comps[0].ecosystem == "npm"


class TestParseGoMod:
    def test_parses_require_block(self, tmp_path: Path) -> None:
        f = tmp_path / "go.mod"
        f.write_text("module m\ngo 1.21\nrequire (\n  github.com/gin-gonic/gin v1.9.1\n)\n")
        comps = parse_go_mod(f)
        assert len(comps) == 1
        assert comps[0].name == "github.com/gin-gonic/gin"


class TestComponent:
    def test_to_cyclonedx(self) -> None:
        c = Component("requests", "2.28.0", "pkg:pypi/requests@2.28.0", "PyPI", licenses=["MIT"])
        d = c.to_cyclonedx()
        assert d["name"] == "requests"
        assert d["version"] == "2.28.0"
        assert d["purl"] == "pkg:pypi/requests@2.28.0"
        assert d["licenses"][0]["license"]["id"] == "MIT"

    def test_to_spdx(self) -> None:
        c = Component("flask", "2.0.0", "pkg:pypi/flask@2.0.0", "PyPI")
        d = c.to_spdx()
        assert d["name"] == "flask"
        assert "SPDXID" in d


class TestSBOMDocument:
    def _make_doc(self) -> SBOMDocument:
        comps = [
            Component("requests", "2.28.0", "pkg:pypi/requests@2.28.0", "PyPI"),
            Component("flask", "2.3.0", "pkg:pypi/flask@2.3.0", "PyPI"),
        ]
        return SBOMDocument.from_components(comps, "requirements.txt")

    def test_cyclonedx_format(self) -> None:
        doc = self._make_doc()
        d = doc.to_cyclonedx()
        assert d["bomFormat"] == "CycloneDX"
        assert len(d["components"]) == 2

    def test_spdx_format(self) -> None:
        doc = self._make_doc()
        d = doc.to_spdx()
        assert "spdxVersion" in d
        assert len(d["packages"]) == 2

    def test_summary(self) -> None:
        doc = self._make_doc()
        s = doc.summary()
        assert s["total_components"] == 2
        assert s["by_ecosystem"]["PyPI"] == 2

    def test_serial_number_unique(self) -> None:
        doc1 = self._make_doc()
        doc2 = self._make_doc()
        assert doc1.serial_number != doc2.serial_number


class TestDetectAndParse:
    def test_requirements(self, tmp_path: Path) -> None:
        f = tmp_path / "requirements.txt"
        f.write_text("click==8.1.0\n")
        comps = detect_and_parse(f)
        assert comps[0].ecosystem == "PyPI"

    def test_unsupported_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "Pipfile"
        f.write_text("[packages]\n")
        with pytest.raises(ValueError):
            detect_and_parse(f)
