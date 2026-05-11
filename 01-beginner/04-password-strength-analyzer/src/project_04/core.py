"""Password strength analysis: entropy, character classes, and pattern detection."""

from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, field

# Character-class pool sizes for entropy estimation
_POOL_LOWER: int = len(string.ascii_lowercase)   # 26
_POOL_UPPER: int = len(string.ascii_uppercase)   # 26
_POOL_DIGITS: int = len(string.digits)           # 10
_POOL_SPECIAL: int = len(string.punctuation)     # 32

# Policy thresholds
MIN_LENGTH: int = 8
STRONG_LENGTH: int = 16
MIN_ENTROPY_BITS_FAIR: float = 40.0
MIN_ENTROPY_BITS_STRONG: float = 60.0
MIN_ENTROPY_BITS_VERY_STRONG: float = 80.0

# Common password patterns to flag
_KEYBOARD_WALKS = re.compile(
    r"(qwert|asdf|zxcv|qazwsx|1qaz|2wsx|password|letmein|admin|"
    r"welcome|monkey|dragon|master|sunshine|princess)",
    re.IGNORECASE,
)
_DATE_PATTERN = re.compile(r"\b(19|20)\d{2}[0-1]\d[0-3]\d\b|\b\d{2}[/-]\d{2}[/-]\d{2,4}\b")
_REPEAT_PATTERN = re.compile(r"(.)\1{2,}")  # same char repeated 3+


@dataclass(frozen=True)
class PasswordAnalysis:
    """Full analysis result for a single password."""

    password_length: int
    entropy_bits: float
    has_lower: bool
    has_upper: bool
    has_digits: bool
    has_special: bool
    score: int          # 0 (very weak) – 4 (very strong)
    strength_label: str
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


_SCORE_LABELS: dict[int, str] = {
    0: "Very Weak",
    1: "Weak",
    2: "Fair",
    3: "Strong",
    4: "Very Strong",
}


def analyze_password(password: str) -> PasswordAnalysis:
    """Analyse *password* and return a :class:`PasswordAnalysis`.

    Args:
        password: The plaintext password to evaluate.

    Returns:
        Structured analysis with score, entropy, and actionable suggestions.
    """
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digits = any(c in string.digits for c in password)
    has_special = any(c in string.punctuation for c in password)

    pool = _calculate_pool(has_lower, has_upper, has_digits, has_special)
    entropy = _calculate_entropy(len(password), pool)

    warnings, suggestions = _generate_feedback(
        password, entropy, has_lower, has_upper, has_digits, has_special
    )
    score = _calculate_score(entropy, len(password), warnings)
    return PasswordAnalysis(
        password_length=len(password),
        entropy_bits=round(entropy, 2),
        has_lower=has_lower,
        has_upper=has_upper,
        has_digits=has_digits,
        has_special=has_special,
        score=score,
        strength_label=_SCORE_LABELS[score],
        warnings=warnings,
        suggestions=suggestions,
    )


def _calculate_pool(lower: bool, upper: bool, digits: bool, special: bool) -> int:
    """Sum of character class sizes present in the password."""
    pool = 0
    if lower:
        pool += _POOL_LOWER
    if upper:
        pool += _POOL_UPPER
    if digits:
        pool += _POOL_DIGITS
    if special:
        pool += _POOL_SPECIAL
    return max(pool, 1)


def _calculate_entropy(length: int, pool: int) -> float:
    """Compute naive entropy: length * log2(pool)."""
    if length == 0 or pool <= 1:
        return 0.0
    return length * math.log2(pool)


def _generate_feedback(
    password: str,
    entropy: float,
    lower: bool,
    upper: bool,
    digits: bool,
    special: bool,
) -> tuple[list[str], list[str]]:
    """Return (warnings, suggestions) lists for the given password."""
    warnings: list[str] = []
    suggestions: list[str] = []

    if len(password) < MIN_LENGTH:
        warnings.append(f"Too short (minimum {MIN_LENGTH} characters)")
    if not lower:
        suggestions.append("Add lowercase letters")
    if not upper:
        suggestions.append("Add uppercase letters")
    if not digits:
        suggestions.append("Add digits")
    if not special:
        suggestions.append("Add special characters (!@#$...)")
    if _KEYBOARD_WALKS.search(password):
        warnings.append("Contains common keyboard walk or dictionary word")
    if _DATE_PATTERN.search(password):
        warnings.append("Contains what appears to be a date")
    if _REPEAT_PATTERN.search(password):
        warnings.append("Contains repeated characters (e.g. 'aaa')")
    if len(password) < STRONG_LENGTH:
        suggestions.append(f"Use at least {STRONG_LENGTH} characters for strong security")
    if entropy < MIN_ENTROPY_BITS_FAIR:
        suggestions.append("Increase password complexity significantly")

    return warnings, suggestions


def _calculate_score(entropy: float, length: int, warnings: list[str]) -> int:
    """Compute 0–4 score from entropy and penalty for warnings."""
    if entropy >= MIN_ENTROPY_BITS_VERY_STRONG and length >= STRONG_LENGTH:
        base = 4
    elif entropy >= MIN_ENTROPY_BITS_STRONG:
        base = 3
    elif entropy >= MIN_ENTROPY_BITS_FAIR:
        base = 2
    elif entropy >= MIN_ENTROPY_BITS_FAIR / 2:
        base = 1
    else:
        base = 0
    penalty = min(len(warnings), base)
    return max(0, base - penalty)
