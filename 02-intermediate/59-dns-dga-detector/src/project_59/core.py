"""DGA domain detection using entropy, n-gram, and heuristic analysis."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# English bigram frequency (top 20)
ENGLISH_BIGRAMS: Final[dict[str, float]] = {
    "th": 0.0356, "he": 0.0307, "in": 0.0243, "er": 0.0205, "an": 0.0199,
    "re": 0.0185, "on": 0.0176, "at": 0.0149, "en": 0.0145, "nd": 0.0135,
    "ti": 0.0134, "es": 0.0134, "or": 0.0128, "te": 0.0120, "of": 0.0117,
    "ed": 0.0117, "is": 0.0113, "it": 0.0112, "al": 0.0109, "ar": 0.0107,
}

# Alexa/Tranco top domains – used as a compact whitelist sample
TOP_DOMAIN_KEYWORDS: Final[frozenset[str]] = frozenset({
    "google", "youtube", "facebook", "amazon", "microsoft",
    "apple", "twitter", "instagram", "linkedin", "github",
    "wikipedia", "reddit", "netflix", "yahoo", "bing",
})

CONSONANT_RE: Final[re.Pattern[str]] = re.compile(r"[^aeiou]", re.IGNORECASE)
DIGIT_RE: Final[re.Pattern[str]] = re.compile(r"\d")
NON_ALPHA_RE: Final[re.Pattern[str]] = re.compile(r"[^a-z]")

MIN_DGA_LEN: Final[int] = 6
MAX_REAL_LEN: Final[int] = 20


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def consonant_ratio(label: str) -> float:
    """Ratio of consonants to total alphabetic characters."""
    alpha = re.sub(r"[^a-z]", "", label.lower())
    if not alpha:
        return 0.0
    consonants = len(CONSONANT_RE.findall(alpha))
    return consonants / len(alpha)


def digit_ratio(label: str) -> float:
    """Ratio of digits to total characters."""
    if not label:
        return 0.0
    return len(DIGIT_RE.findall(label)) / len(label)


def bigram_score(label: str) -> float:
    """Mean bigram frequency based on English bigram table (higher = more English-like)."""
    s = NON_ALPHA_RE.sub("", label.lower())
    if len(s) < 2:
        return 0.0
    total = sum(ENGLISH_BIGRAMS.get(s[i: i + 2], 0.0) for i in range(len(s) - 1))
    return total / (len(s) - 1)


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

@dataclass
class DGAVerdict:
    """Result of DGA analysis for a single domain."""

    domain: str
    label: str              # first label before first dot
    is_dga: bool
    confidence: float       # 0.0 – 1.0
    entropy: float
    consonant_ratio: float
    digit_ratio: float
    bigram_score: float
    length: int
    reason: str


def classify_domain(domain: str) -> DGAVerdict:
    """Classify a domain as DGA-generated or benign."""
    domain = domain.lower().strip().rstrip(".")
    # Extract the most-significant label (skip TLD)
    parts = domain.split(".")
    if len(parts) >= 2:
        label = parts[-2]
    else:
        label = parts[0]

    length = len(label)
    ent = shannon_entropy(label)
    crat = consonant_ratio(label)
    drat = digit_ratio(label)
    bscore = bigram_score(label)

    # Whitelist: known good keywords
    if any(kw in label for kw in TOP_DOMAIN_KEYWORDS):
        return DGAVerdict(
            domain=domain, label=label, is_dga=False, confidence=0.05,
            entropy=ent, consonant_ratio=crat, digit_ratio=drat,
            bigram_score=bscore, length=length, reason="whitelist_keyword",
        )

    # Short labels are likely benign
    if length < MIN_DGA_LEN:
        return DGAVerdict(
            domain=domain, label=label, is_dga=False, confidence=0.1,
            entropy=ent, consonant_ratio=crat, digit_ratio=drat,
            bigram_score=bscore, length=length, reason="too_short",
        )

    # Score heuristics → confidence
    score = 0.0
    reasons: list[str] = []

    if ent > 3.5:
        score += 0.35
        reasons.append(f"high_entropy({ent:.2f})")

    if crat > 0.72:
        score += 0.25
        reasons.append(f"high_consonant_ratio({crat:.2f})")

    if drat > 0.25:
        score += 0.15
        reasons.append(f"high_digit_ratio({drat:.2f})")

    if bscore < 0.003:
        score += 0.20
        reasons.append(f"low_bigram({bscore:.4f})")

    if length > MAX_REAL_LEN:
        score += 0.15
        reasons.append(f"long_label({length})")

    confidence = min(score, 1.0)
    is_dga = confidence >= 0.5

    return DGAVerdict(
        domain=domain, label=label, is_dga=is_dga, confidence=round(confidence, 3),
        entropy=round(ent, 3), consonant_ratio=round(crat, 3),
        digit_ratio=round(drat, 3), bigram_score=round(bscore, 4),
        length=length, reason=", ".join(reasons) or "benign",
    )


def analyse_domain_list(domains: list[str]) -> list[DGAVerdict]:
    """Classify a list of domains."""
    return [classify_domain(d) for d in domains if d.strip()]
