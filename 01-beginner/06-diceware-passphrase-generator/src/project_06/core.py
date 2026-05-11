"""Core logic: wordlist loading, passphrase generation, entropy calculation."""

from __future__ import annotations

import math
import secrets
from pathlib import Path

from project_06._wordlist import DEMO_WORDLIST

DEFAULT_WORD_COUNT: int = 6
DEFAULT_SEPARATOR: str = "-"
MIN_WORD_COUNT: int = 3
RECOMMENDED_MIN_ENTROPY: float = 77.0  # NIST recommendation


def load_wordlist(path: Path | None = None) -> list[str]:
    """Load a wordlist from *path*, or return the bundled demo list.

    The file format is one word per line (EFF-compatible).

    Args:
        path: Optional path to a custom wordlist file.  If the file contains
              tab-separated entries (EFF format: ``11111\\tword``), only the
              word portion is kept.

    Returns:
        Deduplicated, sorted list of lowercase words.

    Raises:
        FileNotFoundError: If *path* is provided but does not exist.
        ValueError: If the resulting wordlist has fewer than 2 words.
    """
    if path is None:
        return list(DEMO_WORDLIST)
    if not path.exists():
        raise FileNotFoundError(f"Wordlist file not found: {path}")
    words: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        word = line.split("\t")[-1].strip().lower()
        if word:
            words.append(word)
    unique = sorted(set(words))
    if len(unique) < 2:
        raise ValueError(f"Wordlist too small: {len(unique)} unique words (need at least 2)")
    return unique


def generate_passphrase(
    word_count: int = DEFAULT_WORD_COUNT,
    wordlist: list[str] | None = None,
    separator: str = DEFAULT_SEPARATOR,
) -> str:
    """Generate a Diceware-style passphrase using the OS CSPRNG.

    Each word is chosen with :func:`secrets.choice` — never :mod:`random`.

    Args:
        word_count: Number of words in the passphrase.
        wordlist: Word pool to draw from; defaults to bundled demo list.
        separator: String inserted between words.

    Returns:
        Passphrase string with words joined by *separator*.

    Raises:
        ValueError: If *word_count* is below :const:`MIN_WORD_COUNT`.
    """
    if word_count < MIN_WORD_COUNT:
        raise ValueError(
            f"Word count must be at least {MIN_WORD_COUNT}, got {word_count}"
        )
    pool = wordlist if wordlist is not None else list(DEMO_WORDLIST)
    words = [secrets.choice(pool) for _ in range(word_count)]
    return separator.join(words)


def passphrase_entropy(word_count: int, wordlist_size: int) -> float:
    """Calculate passphrase entropy in bits.

    Args:
        word_count: Number of words in the passphrase.
        wordlist_size: Total number of words in the wordlist.

    Returns:
        Entropy in bits: ``word_count × log₂(wordlist_size)``.
    """
    if wordlist_size < 2 or word_count < 1:
        return 0.0
    return round(word_count * math.log2(wordlist_size), 2)


def entropy_warning(entropy: float) -> str | None:
    """Return a warning string if *entropy* is below the recommended minimum.

    Args:
        entropy: Passphrase entropy in bits.

    Returns:
        Warning string, or ``None`` if entropy is sufficient.
    """
    if entropy < RECOMMENDED_MIN_ENTROPY:
        return (
            f"Entropy {entropy:.1f} bits is below the recommended "
            f"{RECOMMENDED_MIN_ENTROPY:.0f} bits (NIST SP 800-63B). "
            "Consider using more words or the full EFF large wordlist."
        )
    return None
