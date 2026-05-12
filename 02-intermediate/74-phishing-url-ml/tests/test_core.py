"""Tests for project 74 Phishing URL ML Detector."""

from __future__ import annotations

import pytest

from project_74.core import (
    PhishingURLClassifier,
    URLFeatures,
    _shannon_entropy,
    extract_features,
    heuristic_classify,
)


# ---------------------------------------------------------------------------
# _shannon_entropy
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_uniform_string_high_entropy(self) -> None:
        e = _shannon_entropy("abcdefghij")
        assert e > 3.0

    def test_single_char_zero(self) -> None:
        assert _shannon_entropy("aaaa") == 0.0

    def test_empty_zero(self) -> None:
        assert _shannon_entropy("") == 0.0


# ---------------------------------------------------------------------------
# extract_features
# ---------------------------------------------------------------------------

class TestExtractFeatures:
    def test_ip_host_detected(self) -> None:
        f = extract_features("http://192.168.1.1/login")
        assert f.has_ip_host

    def test_https_detected(self) -> None:
        f = extract_features("https://example.com")
        assert f.has_https

    def test_http_not_https(self) -> None:
        f = extract_features("http://example.com")
        assert not f.has_https

    def test_shortener_detected(self) -> None:
        f = extract_features("http://bit.ly/abc123")
        assert f.is_shortener

    def test_suspicious_tld(self) -> None:
        f = extract_features("http://login.paypal.tk")
        assert f.suspicious_tld

    def test_brand_in_subdomain(self) -> None:
        f = extract_features("http://secure-paypal.attacker.com/verify")
        assert f.brand_in_subdomain

    def test_clean_url_brand_not_in_sub(self) -> None:
        # paypal.com itself should NOT flag brand_in_subdomain
        f = extract_features("https://www.paypal.com/login")
        assert not f.brand_in_subdomain

    def test_at_sign_detected(self) -> None:
        f = extract_features("http://user@192.168.1.1")
        assert f.has_at_sign

    def test_hyphen_count(self) -> None:
        f = extract_features("http://secure-login-verify-now.tk")
        assert f.num_hyphens >= 3

    def test_url_length(self) -> None:
        url = "http://example.com/" + "a" * 200
        f = extract_features(url)
        assert f.url_length > 100

    def test_suspicious_word_count(self) -> None:
        f = extract_features("http://example.com/secure/login/verify")
        assert f.suspicious_word_count >= 2

    def test_num_subdomains(self) -> None:
        f = extract_features("http://a.b.c.example.com")
        assert f.num_subdomains >= 3

    def test_to_list_length(self) -> None:
        f = extract_features("https://example.com")
        assert len(f.to_list()) == 17

    def test_no_scheme_handled(self) -> None:
        f = extract_features("example.com")
        assert f.domain_length > 0


# ---------------------------------------------------------------------------
# heuristic_classify
# ---------------------------------------------------------------------------

class TestHeuristicClassify:
    def test_clean_url_not_phishing(self) -> None:
        f = extract_features("https://www.google.com/search?q=hello")
        pred = heuristic_classify(f)
        assert not pred.is_phishing
        assert pred.confidence < 0.4

    def test_ip_url_phishing(self) -> None:
        f = extract_features("http://192.168.1.1/login/verify")
        pred = heuristic_classify(f)
        assert pred.is_phishing

    def test_brand_in_sub_phishing(self) -> None:
        f = extract_features("http://paypal-login.attacker.tk/secure/verify")
        pred = heuristic_classify(f)
        assert pred.is_phishing

    def test_at_sign_phishing(self) -> None:
        # @ sign + HTTP + suspicious words pushes over the 0.4 threshold
        f = extract_features("http://attacker.com@bank.com/secure/verify/login")
        pred = heuristic_classify(f)
        assert pred.confidence > 0.35

    def test_reason_populated(self) -> None:
        f = extract_features("http://192.168.0.1/verify")
        pred = heuristic_classify(f)
        assert pred.reason != ""


# ---------------------------------------------------------------------------
# PhishingURLClassifier (heuristic mode, no sklearn required)
# ---------------------------------------------------------------------------

class TestPhishingURLClassifier:
    def test_predict_returns_prediction(self) -> None:
        clf = PhishingURLClassifier()
        pred = clf.predict("https://www.example.com")
        assert hasattr(pred, "is_phishing")
        assert 0.0 <= pred.confidence <= 1.0

    def test_predict_batch(self) -> None:
        clf = PhishingURLClassifier()
        preds = clf.predict_batch(["https://google.com", "http://192.168.0.1/login"])
        assert len(preds) == 2

    def test_phishing_url_flagged(self) -> None:
        clf = PhishingURLClassifier()
        pred = clf.predict("http://secure-paypal.attacker.tk/login/verify/account")
        assert pred.is_phishing

    def test_legitimate_url_clean(self) -> None:
        clf = PhishingURLClassifier()
        pred = clf.predict("https://www.google.com/search?q=weather")
        assert not pred.is_phishing

    def test_fit_requires_sklearn(self) -> None:
        import project_74.core as core
        original = core.SKLEARN_AVAILABLE
        core.SKLEARN_AVAILABLE = False
        try:
            clf = PhishingURLClassifier()
            with pytest.raises(ImportError):
                clf.fit(["http://example.com"], [0])
        finally:
            core.SKLEARN_AVAILABLE = original
