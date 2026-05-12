"""Tests for project 57 STIX/TAXII parser."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from project_57.core import STIXBundle, STIXIndicator, STIXObject, STIXType

SAMPLE_BUNDLE = {
    "type": "bundle",
    "id": "bundle--12345678-1234-1234-1234-123456789012",
    "spec_version": "2.1",
    "objects": [
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--aaaaaaaa-0000-0000-0000-000000000001",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "name": "Malicious IP",
            "description": "Known C2 server",
            "pattern": "[ipv4-addr:value = '10.0.0.1']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00Z",
            "kill_chain_phases": [{"phase_name": "command-and-control", "kill_chain_name": "mitre"}],
            "labels": ["malicious-activity"],
        },
        {
            "type": "malware",
            "spec_version": "2.1",
            "id": "malware--bbbbbbbb-0000-0000-0000-000000000002",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "name": "EvilRAT",
            "description": "Remote access trojan",
            "malware_types": ["trojan"],
            "is_family": False,
        },
        {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": "threat-actor--cccccccc-0000-0000-0000-000000000003",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "name": "APT99",
        },
    ],
}


class TestSTIXBundle:
    def test_from_dict(self) -> None:
        bundle = STIXBundle.from_dict(SAMPLE_BUNDLE)
        assert bundle.bundle_id.startswith("bundle--")
        assert len(bundle.objects) == 3

    def test_from_string(self) -> None:
        bundle = STIXBundle.from_string(json.dumps(SAMPLE_BUNDLE))
        assert len(bundle.objects) == 3

    def test_from_file(self, tmp_path: Path) -> None:
        jf = tmp_path / "bundle.json"
        jf.write_text(json.dumps(SAMPLE_BUNDLE))
        bundle = STIXBundle.from_file(jf)
        assert len(bundle.objects) == 3

    def test_indicators_filter(self) -> None:
        bundle = STIXBundle.from_dict(SAMPLE_BUNDLE)
        indicators = bundle.indicators()
        assert len(indicators) == 1
        assert isinstance(indicators[0], STIXIndicator)

    def test_by_type(self) -> None:
        bundle = STIXBundle.from_dict(SAMPLE_BUNDLE)
        malwares = bundle.by_type("malware")
        assert len(malwares) == 1
        assert malwares[0].name == "EvilRAT"

    def test_summary(self) -> None:
        bundle = STIXBundle.from_dict(SAMPLE_BUNDLE)
        summary = bundle.summary()
        assert summary["indicator"] == 1
        assert summary["malware"] == 1
        assert summary["threat-actor"] == 1


class TestSTIXIndicator:
    def _get_indicator(self) -> STIXIndicator:
        bundle = STIXBundle.from_dict(SAMPLE_BUNDLE)
        return bundle.indicators()[0]

    def test_pattern_extracted(self) -> None:
        ind = self._get_indicator()
        assert ind.pattern == "[ipv4-addr:value = '10.0.0.1']"

    def test_ioc_value_extracted(self) -> None:
        ind = self._get_indicator()
        assert ind.extract_ioc_value() == "10.0.0.1"

    def test_kill_chain_phases(self) -> None:
        ind = self._get_indicator()
        assert "command-and-control" in ind.kill_chain_phases

    def test_labels(self) -> None:
        ind = self._get_indicator()
        assert "malicious-activity" in ind.labels


class TestSTIXObject:
    def test_from_dict_generic(self) -> None:
        obj = STIXObject.from_dict({
            "type": "identity",
            "id": "identity--xyz",
            "spec_version": "2.1",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "name": "ACME Corp",
        })
        assert obj.name == "ACME Corp"
        assert obj.stix_type == "identity"
