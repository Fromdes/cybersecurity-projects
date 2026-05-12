"""Phishing URL ML detector — feature extraction + scikit-learn classifier (or heuristic fallback)."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import urlparse

# Soft-import scikit-learn
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS: Final[frozenset[str]] = frozenset({
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link",
    "pw", "work", "men", "bid", "trade", "date", "loan", "stream",
})

LEGITIMATE_BRANDS: Final[frozenset[str]] = frozenset({
    "google", "facebook", "amazon", "paypal", "apple", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "ebay", "chase",
    "wellsfargo", "bankofamerica", "citibank", "hsbc",
})

SHORTENER_DOMAINS: Final[frozenset[str]] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "tiny.cc", "is.gd", "su.pr", "rb.gy",
})

# Regex to detect digits embedded in domain
_DIGITS_RE: Final[re.Pattern[str]] = re.compile(r"\d")
_IP_HOST_RE: Final[re.Pattern[str]] = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_SUSPICIOUS_WORDS_RE: Final[re.Pattern[str]] = re.compile(
    r"(secure|login|verify|account|update|confirm|banking|signin|password|credential)",
    re.IGNORECASE,
)
_AT_SIGN_RE: Final[re.Pattern[str]] = re.compile(r"@")


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

@dataclass
class URLFeatures:
    """Numerical features extracted from a URL for ML classification."""

    url_length: int
    domain_length: int
    path_length: int
    num_dots: int
    num_hyphens: int
    num_digits_in_domain: int
    num_subdomains: int
    has_ip_host: bool
    has_at_sign: bool
    has_https: bool
    is_shortener: bool
    suspicious_tld: bool
    brand_in_subdomain: bool      # e.g. "paypal" in "secure-paypal.attacker.com"
    suspicious_word_count: int
    digit_ratio: float            # digits / total domain chars
    entropy: float                # Shannon entropy of domain string
    double_slash_in_path: bool    # http://attacker.com//redirect?url=http://bank.com
    url: str = ""

    def to_list(self) -> list[float]:
        """Return features as a flat numeric list for ML input."""
        return [
            float(self.url_length),
            float(self.domain_length),
            float(self.path_length),
            float(self.num_dots),
            float(self.num_hyphens),
            float(self.num_digits_in_domain),
            float(self.num_subdomains),
            float(self.has_ip_host),
            float(self.has_at_sign),
            float(self.has_https),
            float(self.is_shortener),
            float(self.suspicious_tld),
            float(self.brand_in_subdomain),
            float(self.suspicious_word_count),
            self.digit_ratio,
            self.entropy,
            float(self.double_slash_in_path),
        ]


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def extract_features(url: str) -> URLFeatures:
    """Extract numerical phishing features from a URL.

    Args:
        url: URL string to analyse.

    Returns:
        URLFeatures dataclass with all computed feature values.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except ValueError:
        return URLFeatures(
            url_length=len(url), domain_length=0, path_length=0,
            num_dots=0, num_hyphens=0, num_digits_in_domain=0,
            num_subdomains=0, has_ip_host=False, has_at_sign=False,
            has_https=False, is_shortener=False, suspicious_tld=False,
            brand_in_subdomain=False, suspicious_word_count=0,
            digit_ratio=0.0, entropy=0.0, double_slash_in_path=False, url=url,
        )

    netloc = parsed.netloc.lower()
    path = parsed.path or ""
    hostname = netloc.split(":")[0]   # strip port
    parts = hostname.split(".")
    tld = parts[-1] if parts else ""

    # Subdomain check: all but last two parts
    subdomains = parts[:-2] if len(parts) > 2 else []
    subdomain_str = ".".join(subdomains)

    # Brand in subdomain (but not in the registered domain)
    brand_in_sub = any(brand in subdomain_str for brand in LEGITIMATE_BRANDS)

    digit_count = len(_DIGITS_RE.findall(hostname))
    total_chars = len(hostname)
    digit_ratio = digit_count / total_chars if total_chars > 0 else 0.0

    return URLFeatures(
        url_length=len(url),
        domain_length=len(hostname),
        path_length=len(path),
        num_dots=url.count("."),
        num_hyphens=hostname.count("-"),
        num_digits_in_domain=digit_count,
        num_subdomains=len(subdomains),
        has_ip_host=bool(_IP_HOST_RE.match(hostname)),
        has_at_sign=bool(_AT_SIGN_RE.search(netloc)),
        has_https=parsed.scheme == "https",
        is_shortener=hostname in SHORTENER_DOMAINS,
        suspicious_tld=tld in SUSPICIOUS_TLDS,
        brand_in_subdomain=brand_in_sub,
        suspicious_word_count=len(_SUSPICIOUS_WORDS_RE.findall(url)),
        digit_ratio=digit_ratio,
        entropy=_shannon_entropy(hostname),
        double_slash_in_path="///" in path or ("//" in path and not path.startswith("//")),
        url=url,
    )


# ---------------------------------------------------------------------------
# Heuristic classifier (fallback when scikit-learn is unavailable)
# ---------------------------------------------------------------------------

@dataclass
class PhishingPrediction:
    """Result of a phishing URL classification."""

    url: str
    is_phishing: bool
    confidence: float   # 0.0–1.0
    features: URLFeatures
    reason: str = ""


def heuristic_classify(features: URLFeatures) -> PhishingPrediction:
    """Classify a URL using rule-based heuristics (no ML required).

    Args:
        features: Pre-extracted URL features.

    Returns:
        PhishingPrediction with heuristic confidence.
    """
    score = 0.0
    reasons: list[str] = []

    if features.has_ip_host:
        score += 0.30
        reasons.append("IP host")
    if features.suspicious_tld:
        score += 0.20
        reasons.append("suspicious TLD")
    if features.brand_in_subdomain:
        score += 0.25
        reasons.append("brand in subdomain")
    if features.is_shortener:
        score += 0.15
        reasons.append("URL shortener")
    if features.suspicious_word_count >= 2:
        score += 0.15
        reasons.append(f"{features.suspicious_word_count} suspicious keywords")
    if features.num_hyphens >= 3:
        score += 0.10
        reasons.append(f"{features.num_hyphens} hyphens in domain")
    if features.url_length > 100:
        score += 0.10
        reasons.append("very long URL")
    if features.has_at_sign:
        score += 0.20
        reasons.append("@ sign in URL")
    if features.double_slash_in_path:
        score += 0.15
        reasons.append("double slash in path")
    if features.num_subdomains >= 3:
        score += 0.10
        reasons.append(f"{features.num_subdomains} subdomains")
    if not features.has_https:
        score += 0.05
        reasons.append("HTTP (not HTTPS)")

    confidence = min(1.0, score)
    return PhishingPrediction(
        url=features.url,
        is_phishing=confidence >= 0.4,
        confidence=confidence,
        features=features,
        reason="; ".join(reasons) if reasons else "no indicators",
    )


# ---------------------------------------------------------------------------
# ML classifier wrapper (uses sklearn if available)
# ---------------------------------------------------------------------------

class PhishingURLClassifier:
    """Phishing URL classifier using RandomForest (or heuristic fallback).

    When scikit-learn is available, train on labelled data using
    ``fit()``. Without scikit-learn, all predictions use the heuristic
    classifier.
    """

    def __init__(self) -> None:
        self._model: object | None = None
        self._trained = False

    def fit(self, urls: list[str], labels: list[int]) -> None:
        """Train the classifier on labelled URLs.

        Args:
            urls: List of URL strings.
            labels: List of labels (1 = phishing, 0 = legitimate).

        Raises:
            ImportError: If scikit-learn is not installed.
        """
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required for ML training. Install with: pip install scikit-learn")

        x = [extract_features(u).to_list() for u in urls]
        pipeline = Pipeline([  # type: ignore[misc]
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(n_estimators=100, random_state=42)),
        ])
        pipeline.fit(x, labels)
        self._model = pipeline
        self._trained = True

    def predict(self, url: str) -> PhishingPrediction:
        """Classify a single URL.

        Args:
            url: URL string to classify.

        Returns:
            PhishingPrediction with confidence and reason.
        """
        features = extract_features(url)

        if self._trained and self._model is not None and SKLEARN_AVAILABLE:
            from sklearn.pipeline import Pipeline as _Pipeline  # type: ignore[assignment]
            model: _Pipeline = self._model  # type: ignore[assignment]
            x = [features.to_list()]
            proba = model.predict_proba(x)[0]
            # proba[1] = probability of class 1 (phishing)
            phishing_prob = float(proba[1])
            return PhishingPrediction(
                url=features.url,
                is_phishing=phishing_prob >= 0.5,
                confidence=phishing_prob,
                features=features,
                reason="ML classifier" if phishing_prob >= 0.5 else "ML classifier (clean)",
            )

        return heuristic_classify(features)

    def predict_batch(self, urls: list[str]) -> list[PhishingPrediction]:
        """Classify a list of URLs.

        Args:
            urls: List of URL strings.

        Returns:
            List of PhishingPrediction objects.
        """
        return [self.predict(u) for u in urls]
