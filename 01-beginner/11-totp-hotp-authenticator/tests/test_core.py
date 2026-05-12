"""Unit tests for project_11.core."""

from __future__ import annotations

import time

import pytest

from project_11.core import (
    DEFAULT_DIGITS,
    TOTPConfig,
    generate_hotp,
    generate_secret,
    generate_totp,
    provisioning_uri,
    verify_hotp,
    verify_totp,
)

# Well-known test secret (base32-encoded "12345678901234567890")
_TEST_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


class TestGenerateSecret:
    def test_returns_base32_string(self) -> None:
        secret = generate_secret()
        import base64
        base64.b32decode(secret)  # raises if invalid

    def test_secrets_are_unique(self) -> None:
        assert generate_secret() != generate_secret()

    def test_length_is_reasonable(self) -> None:
        assert len(generate_secret()) >= 16


class TestTOTP:
    def test_generate_returns_six_digits(self) -> None:
        cfg = TOTPConfig(secret=_TEST_SECRET)
        code = generate_totp(cfg)
        assert len(code) == DEFAULT_DIGITS
        assert code.isdigit()

    def test_verify_valid_code(self) -> None:
        cfg = TOTPConfig(secret=_TEST_SECRET)
        now = time.time()
        code = generate_totp(cfg, at=now)
        assert verify_totp(code, cfg) is True

    def test_verify_wrong_code(self) -> None:
        cfg = TOTPConfig(secret=_TEST_SECRET)
        assert verify_totp("000000", cfg) is False

    def test_codes_change_over_time(self) -> None:
        cfg = TOTPConfig(secret=_TEST_SECRET)
        code_t0 = generate_totp(cfg, at=0.0)
        code_t30 = generate_totp(cfg, at=30.0)
        assert code_t0 != code_t30

    def test_codes_stable_within_interval(self) -> None:
        cfg = TOTPConfig(secret=_TEST_SECRET)
        code_t1 = generate_totp(cfg, at=1.0)
        code_t29 = generate_totp(cfg, at=29.0)
        assert code_t1 == code_t29

    def test_custom_interval(self) -> None:
        cfg = TOTPConfig(secret=_TEST_SECRET, interval=60)
        code = generate_totp(cfg, at=0.0)
        assert len(code) == DEFAULT_DIGITS

    def test_window_accepts_adjacent_step(self) -> None:
        cfg = TOTPConfig(secret=_TEST_SECRET)
        prev_code = generate_totp(cfg, at=time.time() - cfg.interval)
        assert verify_totp(prev_code, cfg, window=1) is True


class TestHOTP:
    def test_generate_returns_six_digits(self) -> None:
        code = generate_hotp(_TEST_SECRET, 0)
        assert len(code) == DEFAULT_DIGITS
        assert code.isdigit()

    def test_counter_changes_code(self) -> None:
        c0 = generate_hotp(_TEST_SECRET, 0)
        c1 = generate_hotp(_TEST_SECRET, 1)
        assert c0 != c1

    def test_negative_counter_raises(self) -> None:
        with pytest.raises(ValueError):
            generate_hotp(_TEST_SECRET, -1)

    def test_verify_valid(self) -> None:
        code = generate_hotp(_TEST_SECRET, 5)
        next_counter = verify_hotp(code, _TEST_SECRET, 5)
        assert next_counter == 6

    def test_verify_invalid(self) -> None:
        assert verify_hotp("000000", _TEST_SECRET, 0) is None

    def test_look_ahead(self) -> None:
        code = generate_hotp(_TEST_SECRET, 3)
        next_counter = verify_hotp(code, _TEST_SECRET, 0, look_ahead=5)
        assert next_counter == 4


class TestProvisioningUri:
    def test_contains_otpauth(self) -> None:
        cfg = TOTPConfig(secret=_TEST_SECRET)
        uri = provisioning_uri(cfg)
        assert uri.startswith("otpauth://totp/")

    def test_contains_secret(self) -> None:
        cfg = TOTPConfig(secret=_TEST_SECRET)
        uri = provisioning_uri(cfg)
        assert _TEST_SECRET in uri

    def test_contains_issuer(self) -> None:
        cfg = TOTPConfig(secret=_TEST_SECRET, issuer="MyApp")
        uri = provisioning_uri(cfg)
        assert "MyApp" in uri
