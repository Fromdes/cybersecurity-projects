"""Unit tests for project_12.core."""

from __future__ import annotations

from pathlib import Path

import pytest

from project_12.core import TOTPParams, generate_uri, render_png, render_terminal

_SECRET = "JBSWY3DPEHPK3PXP"


class TestGenerateUri:
    def test_starts_with_otpauth(self) -> None:
        p = TOTPParams(secret=_SECRET)
        assert generate_uri(p).startswith("otpauth://totp/")

    def test_contains_secret(self) -> None:
        p = TOTPParams(secret=_SECRET)
        assert _SECRET in generate_uri(p)

    def test_contains_issuer(self) -> None:
        p = TOTPParams(secret=_SECRET, issuer="MyApp")
        assert "MyApp" in generate_uri(p)

    def test_contains_account(self) -> None:
        p = TOTPParams(secret=_SECRET, account="alice@example.com")
        assert "alice" in generate_uri(p)

    def test_contains_digits(self) -> None:
        p = TOTPParams(secret=_SECRET, digits=8)
        assert "digits=8" in generate_uri(p)

    def test_contains_period(self) -> None:
        p = TOTPParams(secret=_SECRET, interval=60)
        assert "period=60" in generate_uri(p)

    def test_algorithm_sha1(self) -> None:
        p = TOTPParams(secret=_SECRET)
        assert "algorithm=SHA1" in generate_uri(p)


class TestRenderTerminal:
    def test_returns_string(self) -> None:
        p = TOTPParams(secret=_SECRET)
        uri = generate_uri(p)
        result = render_terminal(uri)
        assert isinstance(result, str)

    def test_multiline(self) -> None:
        p = TOTPParams(secret=_SECRET)
        uri = generate_uri(p)
        lines = render_terminal(uri).splitlines()
        assert len(lines) > 10

    def test_uses_block_chars(self) -> None:
        p = TOTPParams(secret=_SECRET)
        uri = generate_uri(p)
        result = render_terminal(uri)
        assert "██" in result or "  " in result


class TestRenderPng:
    def test_creates_file(self, tmp_path: Path) -> None:
        p = TOTPParams(secret=_SECRET)
        uri = generate_uri(p)
        out = tmp_path / "qr.png"
        render_png(uri, out)
        assert out.exists()
        assert out.stat().st_size > 0

    def test_file_is_png(self, tmp_path: Path) -> None:
        p = TOTPParams(secret=_SECRET)
        uri = generate_uri(p)
        out = tmp_path / "qr.png"
        render_png(uri, out)
        # PNG magic bytes: \x89PNG
        assert out.read_bytes()[:4] == b"\x89PNG"
