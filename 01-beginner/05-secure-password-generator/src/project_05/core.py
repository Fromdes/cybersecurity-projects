"""Core password generation using the `secrets` CSPRNG module."""

from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass

# Character sets
CHARS_LOWER: str = string.ascii_lowercase
CHARS_UPPER: str = string.ascii_uppercase
CHARS_DIGITS: str = string.digits
CHARS_SPECIAL: str = "!@#$%^&*()-_=+[]{}|;:,.<>?"

# Characters that look alike — excluded when unambiguous mode is on
_AMBIGUOUS: frozenset[str] = frozenset("0O1lI")

DEFAULT_LENGTH: int = 16
MIN_LENGTH: int = 8
MAX_LENGTH: int = 512


@dataclass(frozen=True)
class PasswordConfig:
    """Configuration for password generation."""

    length: int = DEFAULT_LENGTH
    use_lower: bool = True
    use_upper: bool = True
    use_digits: bool = True
    use_special: bool = True
    exclude_ambiguous: bool = False
    require_each_class: bool = True

    def __post_init__(self) -> None:
        """Validate configuration."""
        if self.length < MIN_LENGTH:
            raise ValueError(f"Length must be at least {MIN_LENGTH}, got {self.length}")
        if self.length > MAX_LENGTH:
            raise ValueError(f"Length must not exceed {MAX_LENGTH}, got {self.length}")
        if not any([self.use_lower, self.use_upper, self.use_digits, self.use_special]):
            raise ValueError("At least one character class must be enabled")

    def alphabet(self) -> str:
        """Build the full character alphabet from enabled classes."""
        chars = ""
        if self.use_lower:
            chars += CHARS_LOWER
        if self.use_upper:
            chars += CHARS_UPPER
        if self.use_digits:
            chars += CHARS_DIGITS
        if self.use_special:
            chars += CHARS_SPECIAL
        if self.exclude_ambiguous:
            chars = "".join(c for c in chars if c not in _AMBIGUOUS)
        return chars

    def entropy_bits(self) -> float:
        """Estimate password entropy in bits for this configuration."""
        pool = len(self.alphabet())
        if pool <= 1:
            return 0.0
        return round(self.length * math.log2(pool), 2)


def generate_password(config: PasswordConfig | None = None) -> str:
    """Generate a single cryptographically random password.

    Uses :mod:`secrets` (OS CSPRNG) — never :mod:`random`.

    Args:
        config: Generation configuration; defaults to :class:`PasswordConfig` defaults.

    Returns:
        A random password string satisfying *config*.
    """
    cfg = config or PasswordConfig()
    alphabet = cfg.alphabet()

    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(cfg.length))
        if not cfg.require_each_class or _satisfies_requirements(password, cfg):
            return password


def generate_multiple(count: int, config: PasswordConfig | None = None) -> list[str]:
    """Generate *count* unique passwords.

    Args:
        count: Number of passwords to generate.
        config: Shared generation configuration.

    Returns:
        List of *count* unique passwords.

    Raises:
        ValueError: If *count* is less than 1.
    """
    if count < 1:
        raise ValueError(f"Count must be at least 1, got {count}")
    cfg = config or PasswordConfig()
    passwords: list[str] = []
    seen: set[str] = set()
    while len(passwords) < count:
        pw = generate_password(cfg)
        if pw not in seen:
            seen.add(pw)
            passwords.append(pw)
    return passwords


def _satisfies_requirements(password: str, config: PasswordConfig) -> bool:
    """Return True if *password* contains at least one char from each enabled class."""
    checks: list[bool] = []
    alphabet = config.alphabet()
    if config.use_lower:
        lower_chars = set(CHARS_LOWER) & set(alphabet)
        checks.append(any(c in lower_chars for c in password))
    if config.use_upper:
        upper_chars = set(CHARS_UPPER) & set(alphabet)
        checks.append(any(c in upper_chars for c in password))
    if config.use_digits:
        digit_chars = set(CHARS_DIGITS) & set(alphabet)
        checks.append(any(c in digit_chars for c in password))
    if config.use_special:
        special_chars = set(CHARS_SPECIAL) & set(alphabet)
        checks.append(any(c in special_chars for c in password))
    return all(checks)
