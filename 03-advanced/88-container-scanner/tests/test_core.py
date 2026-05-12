"""Tests for Container Image Scanner core."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from project_88.core import (
    ImageFinding,
    ScanResult,
    _check_image_config,
    _scan_tar_for_sensitive_files,
    create_mock_image_tarball,
    scan_image_tarball,
)


class TestCheckImageConfig:
    def test_root_user_flagged(self) -> None:
        config = {"config": {"User": "", "Env": [], "Cmd": []}}
        findings = _check_image_config(config, "test")
        assert any(f.rule_id == "IMG-001" for f in findings)

    def test_nonroot_passes(self) -> None:
        config = {"config": {"User": "appuser", "Env": [], "Cmd": []}}
        findings = _check_image_config(config, "test")
        assert not any(f.rule_id == "IMG-001" for f in findings)

    def test_secret_env_flagged(self) -> None:
        config = {"config": {"User": "app", "Env": ["DB_PASSWORD=secret123"], "Cmd": []}}
        findings = _check_image_config(config, "test")
        assert any(f.rule_id == "IMG-002" for f in findings)

    def test_clean_env_passes(self) -> None:
        config = {"config": {"User": "app", "Env": ["PORT=8080"], "Cmd": []}}
        findings = _check_image_config(config, "test")
        assert not any(f.rule_id == "IMG-002" for f in findings)


class TestScanTarSensitiveFiles:
    def _make_tar_with_file(self, filename: str) -> tarfile.TarFile:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            data = b"content"
            info = tarfile.TarInfo(name=filename)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        buf.seek(0)
        return tarfile.open(fileobj=buf, mode="r")

    def test_shadow_file_flagged(self) -> None:
        tf = self._make_tar_with_file("etc/shadow")
        findings = _scan_tar_for_sensitive_files(tf, "layer0")
        tf.close()
        assert any(f.severity == "CRITICAL" for f in findings)

    def test_private_key_flagged(self) -> None:
        tf = self._make_tar_with_file("home/user/.ssh/id_rsa")
        findings = _scan_tar_for_sensitive_files(tf, "layer0")
        tf.close()
        assert len(findings) >= 1

    def test_env_file_flagged(self) -> None:
        tf = self._make_tar_with_file("app/.env")
        findings = _scan_tar_for_sensitive_files(tf, "layer0")
        tf.close()
        assert len(findings) >= 1

    def test_safe_file_passes(self) -> None:
        tf = self._make_tar_with_file("app/main.py")
        findings = _scan_tar_for_sensitive_files(tf, "layer0")
        tf.close()
        assert findings == []


class TestScanImageTarball:
    def test_root_image_flagged(self, tmp_path: Path) -> None:
        image_tar = tmp_path / "image.tar.gz"
        create_mock_image_tarball(image_tar, config={"config": {"User": "", "Env": [], "Cmd": []}})
        result = scan_image_tarball(image_tar)
        assert isinstance(result, ScanResult)
        assert result.sha256 != ""
        assert any(f.rule_id == "IMG-001" for f in result.findings)

    def test_secure_image_no_critical(self, tmp_path: Path) -> None:
        image_tar = tmp_path / "image.tar.gz"
        create_mock_image_tarball(image_tar, config={"config": {"User": "app", "Env": [], "Cmd": []}})
        result = scan_image_tarball(image_tar)
        critical = [f for f in result.findings if f.severity == "CRITICAL"]
        assert len(critical) == 0

    def test_to_dict(self, tmp_path: Path) -> None:
        image_tar = tmp_path / "image.tar.gz"
        create_mock_image_tarball(image_tar)
        result = scan_image_tarball(image_tar)
        d = result.to_dict()
        assert "sha256" in d
        assert "findings" in d
        assert "total_findings" in d
