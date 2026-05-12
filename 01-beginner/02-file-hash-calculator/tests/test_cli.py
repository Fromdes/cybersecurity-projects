"""CLI tests for project_02."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from project_02.cli import main


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    sys.argv = ["file-hash", *args]
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return int(exc.value.code or 0), captured.out, captured.err


class TestHashCLI:
    def test_hash_text(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["hash", "--text", "hello"], capsys)
        assert code == 0
        assert "sha256" in out

    def test_hash_text_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, out, _ = _run(["hash", "--text", "hello", "--json"], capsys)
        assert code == 0
        data = json.loads(out)
        assert "digest" in data

    def test_hash_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        f = tmp_path / "t.txt"
        f.write_bytes(b"test")
        code, out, _ = _run(["hash", "--file", str(f)], capsys)
        assert code == 0
        assert "sha256" in out

    def test_hash_file_all(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        f = tmp_path / "t.txt"
        f.write_bytes(b"test")
        code, out, _ = _run(["hash", "--file", str(f), "--all"], capsys)
        assert code == 0
        assert "sha256" in out

    def test_hash_missing_file(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, _, _err = _run(["hash", "--file", "/nonexistent/path.txt"], capsys)
        assert code == 1

    def test_all_requires_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, _, _err = _run(["hash", "--text", "hi", "--all"], capsys)
        assert code == 1


class TestVerifyCLI:
    def test_verify_correct(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        from project_02.core import hash_file
        f = tmp_path / "v.txt"
        f.write_bytes(b"verify")
        digest = hash_file(f, "sha256")
        code, out, _ = _run(["verify", str(f), digest], capsys)
        assert code == 0
        assert "OK" in out

    def test_verify_mismatch(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        f = tmp_path / "v.txt"
        f.write_bytes(b"data")
        code, out, _ = _run(["verify", str(f), "aabbcc"], capsys)
        assert code == 2
        assert "MISMATCH" in out

    def test_verify_missing_file(self, capsys: pytest.CaptureFixture[str]) -> None:
        code, _, _err = _run(["verify", "/no/such/file.txt", "aabb"], capsys)
        assert code == 1
