"""Core cipher logic: Caesar, Vigenere, frequency analysis, and crack utilities."""

from __future__ import annotations

import math
import string

# English letter frequency table (source: Cornell University, relative percentages)
ENGLISH_FREQ: dict[str, float] = {
    "A": 8.167, "B": 1.492, "C": 2.782, "D": 4.253, "E": 12.702,
    "F": 2.228, "G": 2.015, "H": 6.094, "I": 6.966, "J": 0.153,
    "K": 0.772, "L": 4.025, "M": 2.406, "N": 6.749, "O": 7.507,
    "P": 1.929, "Q": 0.095, "R": 5.987, "S": 6.327, "T": 9.056,
    "U": 2.758, "V": 0.978, "W": 2.360, "X": 0.150, "Y": 1.974,
    "Z": 0.074,
}

ALPHABET: str = string.ascii_uppercase
ALPHABET_SIZE: int = len(ALPHABET)
_ORD_A: int = ord("A")


class CaesarCipher:
    """Caesar cipher: rotate each letter by a fixed shift.

    Demonstrates why single-substitution ciphers are trivially broken via
    frequency analysis (MITRE T1027 – Obfuscated Files or Information).
    """

    def __init__(self, shift: int) -> None:
        """Initialise with a shift value 0–25."""
        if not 0 <= shift < ALPHABET_SIZE:
            raise ValueError(f"Shift must be 0–{ALPHABET_SIZE - 1}, got {shift}")
        self.shift = shift % ALPHABET_SIZE

    def encrypt(self, plaintext: str) -> str:
        """Encrypt *plaintext*; non-alpha characters are preserved unchanged."""
        return self._transform(plaintext, self.shift)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt *ciphertext* using the stored shift."""
        return self._transform(ciphertext, ALPHABET_SIZE - self.shift)

    @staticmethod
    def _transform(text: str, shift: int) -> str:
        """Apply a rotational shift to every alphabetic character in *text*."""
        result: list[str] = []
        for ch in text:
            if ch.isalpha():
                base = _ORD_A if ch.isupper() else ord("a")
                shifted = (ord(ch) - base + shift) % ALPHABET_SIZE
                result.append(chr(shifted + base))
            else:
                result.append(ch)
        return "".join(result)


class VigenereCipher:
    """Vigenere cipher: polyalphabetic substitution using a repeating keyword.

    Harder to break than Caesar but still vulnerable to Kasiski / Index of
    Coincidence attacks. Illustrates why short, predictable keys fail.
    """

    def __init__(self, key: str) -> None:
        """Initialise with an alphabetic key (case-insensitive)."""
        if not key.isalpha():
            raise ValueError("Vigenere key must contain only letters")
        self._key = key.upper()

    def encrypt(self, plaintext: str) -> str:
        """Encrypt *plaintext* with the Vigenere cipher."""
        return self._transform(plaintext, encrypt=True)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt *ciphertext* with the Vigenere cipher."""
        return self._transform(ciphertext, encrypt=False)

    def _transform(self, text: str, *, encrypt: bool) -> str:
        """Apply the Vigenere transformation to *text*."""
        result: list[str] = []
        key_idx = 0
        for ch in text:
            if ch.isalpha():
                k = ord(self._key[key_idx % len(self._key)]) - _ORD_A
                shift = k if encrypt else ALPHABET_SIZE - k
                base = _ORD_A if ch.isupper() else ord("a")
                shifted = (ord(ch) - base + shift) % ALPHABET_SIZE
                result.append(chr(shifted + base))
                key_idx += 1
            else:
                result.append(ch)
        return "".join(result)


def frequency_analysis(text: str) -> dict[str, float]:
    """Return letter-frequency percentages for *text* (uppercase keys).

    Args:
        text: Any string; non-alphabetic characters are ignored.

    Returns:
        Mapping from uppercase letter to percentage of total letters.
    """
    counts: dict[str, int] = dict.fromkeys(ALPHABET, 0)
    total = 0
    for ch in text.upper():
        if ch in counts:
            counts[ch] += 1
            total += 1
    if total == 0:
        return dict.fromkeys(ALPHABET, 0.0)
    return {ch: round(counts[ch] / total * 100, 3) for ch in ALPHABET}


def _chi_squared(observed: dict[str, float]) -> float:
    """Compute chi-squared distance from English letter frequencies."""
    return sum(
        (observed[ch] - ENGLISH_FREQ[ch]) ** 2 / ENGLISH_FREQ[ch]
        for ch in ALPHABET
    )


def caesar_crack(ciphertext: str) -> list[tuple[int, str]]:
    """Brute-force all 25 Caesar shifts, ranked by English frequency fit.

    Args:
        ciphertext: The encrypted message.

    Returns:
        List of (shift, plaintext) tuples, best chi-squared match first.
    """
    results: list[tuple[float, int, str]] = []
    for shift in range(1, ALPHABET_SIZE):
        candidate = CaesarCipher(shift).decrypt(ciphertext)
        freq = frequency_analysis(candidate)
        score = _chi_squared(freq)
        results.append((score, shift, candidate))
    results.sort()
    return [(shift, text) for _, shift, text in results]


def vigenere_key_length_hint(ciphertext: str, max_key_len: int = 10) -> list[tuple[int, float]]:
    """Estimate Vigenere key length using Index of Coincidence.

    Args:
        ciphertext: The encrypted message (letters only).
        max_key_len: Maximum key length to test.

    Returns:
        List of (key_length, IoC) sorted by IoC descending (English IoC ≈ 0.065).
    """
    letters = [ch.upper() for ch in ciphertext if ch.isalpha()]
    results: list[tuple[int, float]] = []
    for length in range(1, min(max_key_len + 1, len(letters))):
        ioc = _index_of_coincidence(letters[::length])
        results.append((length, round(ioc, 4)))
    results.sort(key=lambda x: abs(x[1] - 0.065))
    return results


def _index_of_coincidence(letters: list[str]) -> float:
    """Compute the Index of Coincidence for a sequence of letters."""
    n = len(letters)
    if n < 2:
        return 0.0
    counts = {ch: letters.count(ch) for ch in set(letters)}
    numerator = sum(c * (c - 1) for c in counts.values())
    denominator = n * (n - 1)
    return numerator / denominator if denominator else 0.0


def entropy_bits(text: str) -> float:
    """Estimate Shannon entropy (bits) of a string.

    Args:
        text: Input string.

    Returns:
        Shannon entropy in bits.
    """
    if not text:
        return 0.0
    freq = frequency_analysis(text.upper())
    total = sum(1 for ch in text if ch.isalpha())
    if total == 0:
        return 0.0
    entropy = 0.0
    for p in freq.values():
        p_frac = p / 100
        if p_frac > 0:
            entropy -= p_frac * math.log2(p_frac)
    return round(entropy, 4)
