"""TOTP (RFC 6238) and HOTP (RFC 4226) generation and verification."""

from __future__ import annotations

import time
from dataclasses import dataclass

import pyotp

# RFC 6238 defaults
DEFAULT_DIGITS: int = 6
DEFAULT_INTERVAL: int = 30      # seconds per TOTP step
DEFAULT_ALGORITHM: str = "SHA1"
DEFAULT_WINDOW: int = 1         # ±1 step for clock skew tolerance

# Minimum acceptable shared-secret length
MIN_SECRET_BYTES: int = 20      # 160 bits


@dataclass(frozen=True)
class TOTPConfig:
    """Configuration for a TOTP credential."""

    secret: str          # base32-encoded shared secret
    issuer: str = "DefensivePortfolio"
    account: str = "user@example.com"
    digits: int = DEFAULT_DIGITS
    interval: int = DEFAULT_INTERVAL


def generate_secret() -> str:
    """Generate a cryptographically random base32 secret (32 chars = 160 bits).

    Returns:
        Uppercase base32 string suitable for TOTP/HOTP shared secrets.
    """
    return pyotp.random_base32()


def generate_totp(config: TOTPConfig, *, at: float | None = None) -> str:
    """Generate the current TOTP code for *config*.

    Args:
        config: TOTP credential configuration.
        at: UNIX timestamp override (default: current time).

    Returns:
        Zero-padded decimal OTP string (``digits`` characters long).
    """
    totp = pyotp.TOTP(
        config.secret,
        digits=config.digits,
        interval=config.interval,
    )
    timestamp = at if at is not None else time.time()
    return totp.at(int(timestamp))


def verify_totp(code: str, config: TOTPConfig, *, window: int = DEFAULT_WINDOW) -> bool:
    """Verify a TOTP *code* allowing ±*window* time steps for clock skew.

    Args:
        code: OTP string submitted by the user.
        config: TOTP credential configuration matching the user's authenticator.
        window: Number of adjacent time steps to accept (default 1 = ±30 s).

    Returns:
        ``True`` if the code is valid within the window.
    """
    totp = pyotp.TOTP(
        config.secret,
        digits=config.digits,
        interval=config.interval,
    )
    return totp.verify(code, valid_window=window)


def generate_hotp(secret: str, counter: int, *, digits: int = DEFAULT_DIGITS) -> str:
    """Generate an HOTP code for *counter*.

    Args:
        secret: Base32-encoded shared secret.
        counter: Event counter (must match the server's expected counter).
        digits: OTP length (default 6).

    Returns:
        Zero-padded decimal OTP string.

    Raises:
        ValueError: If *counter* is negative.
    """
    if counter < 0:
        raise ValueError(f"Counter must be non-negative, got {counter}")
    hotp = pyotp.HOTP(secret, digits=digits)
    return hotp.at(counter)


def verify_hotp(
    code: str,
    secret: str,
    counter: int,
    *,
    digits: int = DEFAULT_DIGITS,
    look_ahead: int = 5,
) -> int | None:
    """Verify an HOTP *code* and return the new counter value on success.

    Checks counter values counter..counter+look_ahead to handle desynchronisation.

    Args:
        code: OTP submitted by the user.
        secret: Base32-encoded shared secret.
        counter: Server's current expected counter value.
        digits: OTP length.
        look_ahead: How many future counter values to try.

    Returns:
        Next counter value (counter_matched + 1) if valid, ``None`` otherwise.
    """
    hotp = pyotp.HOTP(secret, digits=digits)
    for offset in range(look_ahead + 1):
        if hotp.verify(code, counter + offset):
            return counter + offset + 1
    return None


def provisioning_uri(config: TOTPConfig) -> str:
    """Return the ``otpauth://`` URI for QR code provisioning.

    Args:
        config: TOTP credential to provision.

    Returns:
        RFC-compliant ``otpauth://totp/...`` URI string.
    """
    totp = pyotp.TOTP(config.secret, digits=config.digits, interval=config.interval)
    return totp.provisioning_uri(name=config.account, issuer_name=config.issuer)
