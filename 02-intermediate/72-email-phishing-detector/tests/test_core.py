"""Tests for project 72 Email Phishing Detector."""

from __future__ import annotations

from project_72.core import (
    PhishingAnalysis,
    analyse_email,
    analyse_urls,
    check_credential_harvest,
    check_sender_anomalies,
    count_keyword_matches,
    count_urgency_words,
    extract_urls,
)

# ---------------------------------------------------------------------------
# Helper to build minimal raw emails
# ---------------------------------------------------------------------------

def _make_email(
    subject: str = "Hello",
    sender: str = "sender@example.com",
    body: str = "Normal email body.",
    reply_to: str = "",
    auth_results: str = "",
    x_mailer: str = "",
    html_only: bool = False,
) -> str:
    headers = [
        f"From: {sender}",
        f"Subject: {subject}",
        "To: victim@example.com",
        "MIME-Version: 1.0",
    ]
    if reply_to:
        headers.append(f"Reply-To: {reply_to}")
    if auth_results:
        headers.append(f"Authentication-Results: {auth_results}")
    if x_mailer:
        headers.append(f"X-Mailer: {x_mailer}")

    if html_only:
        headers.append('Content-Type: text/html; charset="utf-8"')
        headers.append("Content-Transfer-Encoding: quoted-printable")
        body_content = f"<html><body>{body}</body></html>"
    else:
        headers.append('Content-Type: text/plain; charset="utf-8"')
        body_content = body

    return "\r\n".join(headers) + "\r\n\r\n" + body_content


# ---------------------------------------------------------------------------
# extract_urls
# ---------------------------------------------------------------------------

class TestExtractUrls:
    def test_single_url(self) -> None:
        urls = extract_urls("Click http://example.com here")
        assert "http://example.com" in urls

    def test_multiple_urls(self) -> None:
        urls = extract_urls("http://a.com and https://b.com")
        assert len(urls) == 2

    def test_no_urls(self) -> None:
        assert extract_urls("No links here") == []

    def test_deduplication(self) -> None:
        urls = extract_urls("http://x.com http://x.com")
        assert len(urls) == 1


# ---------------------------------------------------------------------------
# count_urgency_words
# ---------------------------------------------------------------------------

class TestCountUrgencyWords:
    def test_urgent_detected(self) -> None:
        assert count_urgency_words("This is urgent! Act now.") >= 2

    def test_no_urgency(self) -> None:
        assert count_urgency_words("Normal message about nothing") == 0


# ---------------------------------------------------------------------------
# count_keyword_matches
# ---------------------------------------------------------------------------

class TestCountKeywordMatches:
    def test_phishing_keyword(self) -> None:
        matches = count_keyword_matches("Please verify your account immediately.")
        assert len(matches) >= 1

    def test_no_keywords(self) -> None:
        assert count_keyword_matches("Meeting at 3pm") == []


# ---------------------------------------------------------------------------
# check_credential_harvest
# ---------------------------------------------------------------------------

class TestCheckCredentialHarvest:
    def test_login_pattern(self) -> None:
        results = check_credential_harvest("Please login here to verify your details.")
        assert len(results) >= 1

    def test_enter_password(self) -> None:
        results = check_credential_harvest("Please enter your password below.")
        assert len(results) >= 1

    def test_clean_text(self) -> None:
        assert check_credential_harvest("See you at the meeting.") == []


# ---------------------------------------------------------------------------
# analyse_urls
# ---------------------------------------------------------------------------

class TestAnalyseUrls:
    def test_url_shortener_detected(self) -> None:
        findings = analyse_urls(["https://bit.ly/abc123"])
        assert any("shortener" in f.lower() for f in findings)

    def test_ip_address_host(self) -> None:
        findings = analyse_urls(["http://192.168.1.1/login"])
        assert any("IP" in f for f in findings)

    def test_suspicious_tld(self) -> None:
        findings = analyse_urls(["http://paypa1.tk/login"])
        assert any("Suspicious TLD" in f for f in findings)

    def test_clean_url(self) -> None:
        assert analyse_urls(["https://www.google.com"]) == []


# ---------------------------------------------------------------------------
# check_sender_anomalies
# ---------------------------------------------------------------------------

class TestCheckSenderAnomalies:
    def test_reply_to_different_domain(self) -> None:
        findings = check_sender_anomalies("admin@bank.com", "reply@attacker.com")
        assert any("Reply-To" in f for f in findings)

    def test_same_domain_no_finding(self) -> None:
        findings = check_sender_anomalies("admin@bank.com", "noreply@bank.com")
        assert not any("Reply-To" in f for f in findings)

    def test_no_reply_to_no_finding(self) -> None:
        findings = check_sender_anomalies("admin@bank.com", "")
        assert not findings


# ---------------------------------------------------------------------------
# analyse_email (integration)
# ---------------------------------------------------------------------------

class TestAnalyseEmail:
    def test_clean_email(self) -> None:
        raw = _make_email(subject="Meeting tomorrow", body="See you at 3pm.")
        result = analyse_email(raw)
        assert result.verdict == "clean"
        assert result.score < 30

    def test_phishing_email_high_score(self) -> None:
        body = (
            "URGENT: Verify your account immediately! Your account will be suspended. "
            "Click here immediately: http://bit.ly/loginverify "
            "Enter your password to confirm your identity."
        )
        raw = _make_email(
            subject="URGENT account warning",
            sender="support@paypa1.tk",
            body=body,
            reply_to="harvest@attacker.xyz",
        )
        result = analyse_email(raw)
        assert result.score >= 60
        assert result.verdict == "phishing"

    def test_subject_urgency_detected(self) -> None:
        raw = _make_email(subject="URGENT: act now or your account expires")
        result = analyse_email(raw)
        assert any(ind.category == "urgency" for ind in result.indicators)

    def test_spf_fail_detected(self) -> None:
        raw = _make_email(
            auth_results="mx.example.com; spf=fail smtp.mailfrom=attacker.com"
        )
        result = analyse_email(raw)
        assert any("SPF" in ind.description for ind in result.indicators)

    def test_html_only_flagged(self) -> None:
        raw = _make_email(body="click here", html_only=True)
        result = analyse_email(raw)
        assert any("HTML-only" in ind.description for ind in result.indicators)

    def test_url_extracted(self) -> None:
        raw = _make_email(body="Visit http://example.com for more info.")
        result = analyse_email(raw)
        assert len(result.urls) >= 1

    def test_score_capped_at_100(self) -> None:
        body = " ".join([kw for kw in list(
            __import__("project_72.core", fromlist=["PHISHING_KEYWORDS"]).PHISHING_KEYWORDS
        )[:15]])
        raw = _make_email(body=body)
        result = analyse_email(raw)
        assert result.score <= 100

    def test_verdict_suspicious_mid_range(self) -> None:
        result = PhishingAnalysis(subject="Test", sender="x@y.com")
        result.add_indicator("keyword", "some keyword", weight=35)
        assert result.verdict == "suspicious"
