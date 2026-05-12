"""Email phishing detector — heuristic + NLP analysis of email content and headers."""

from __future__ import annotations

import email
import email.policy
import re
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PHISHING_KEYWORDS: Final[frozenset[str]] = frozenset({
    "verify your account", "confirm your identity", "update your payment",
    "click here immediately", "urgent action required", "your account will be suspended",
    "unusual sign-in activity", "we detected suspicious", "limited time offer",
    "congratulations you have won", "free gift", "claim your prize",
    "bank account", "social security", "reset your password immediately",
    "you have been selected", "invoice attached", "wire transfer",
    "nigerian prince", "inheritance funds", "lottery winner",
})

URGENCY_WORDS: Final[frozenset[str]] = frozenset({
    "urgent", "immediate", "act now", "expires", "deadline", "warning",
    "alert", "critical", "important notice", "final notice", "last chance",
    "today only", "24 hours", "48 hours", "respond immediately",
})

CREDENTIAL_HARVEST_PATTERNS: Final[list[re.Pattern[str]]] = [
    re.compile(r"enter\s+your\s+(password|pin|credential)", re.IGNORECASE),
    re.compile(r"provide\s+your\s+(ssn|social\s+security|account\s+number)", re.IGNORECASE),
    re.compile(r"login\s+(here|now|below|to\s+verify)", re.IGNORECASE),
    re.compile(r"update\s+your\s+(billing|payment|card\s+information)", re.IGNORECASE),
]

SUSPICIOUS_SENDER_PATTERNS: Final[list[re.Pattern[str]]] = [
    re.compile(r"noreply@(?!(?:google|microsoft|amazon|paypal|apple)\.com)", re.IGNORECASE),
    re.compile(r"@.*\d{4,}", re.IGNORECASE),   # random numbers in domain
    re.compile(r"@[^.]+\.[a-z]{2,3}\.[a-z]{2,3}\.[a-z]{2,3}", re.IGNORECASE),  # deep subdomain
]

URL_RE: Final[re.Pattern[str]] = re.compile(
    r"https?://([^/\s\"'>]+)", re.IGNORECASE
)

# Free URL shorteners
SHORTENER_DOMAINS: Final[frozenset[str]] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "tiny.cc", "is.gd", "su.pr", "rb.gy",
})

MAX_SCORE: Final[int] = 100


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PhishingIndicator:
    """A single phishing indicator found in an email."""

    category: str    # keyword, urgency, url, sender, header, credential
    description: str
    weight: int      # contribution to overall score


@dataclass
class PhishingAnalysis:
    """Complete phishing analysis result for one email."""

    subject: str
    sender: str
    indicators: list[PhishingIndicator] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    score: int = 0

    @property
    def verdict(self) -> str:
        """Return 'phishing', 'suspicious', or 'clean' based on score."""
        if self.score >= 60:
            return "phishing"
        if self.score >= 30:
            return "suspicious"
        return "clean"

    def add_indicator(self, category: str, description: str, weight: int) -> None:
        """Add an indicator and accumulate score (capped at MAX_SCORE)."""
        self.indicators.append(PhishingIndicator(category, description, weight))
        self.score = min(MAX_SCORE, self.score + weight)


# ---------------------------------------------------------------------------
# Feature extractors
# ---------------------------------------------------------------------------

def extract_urls(text: str) -> list[str]:
    """Extract all HTTP/HTTPS URLs from text.

    Args:
        text: Plain text or HTML body.

    Returns:
        List of unique URLs found.
    """
    seen: set[str] = set()
    result: list[str] = []
    for m in URL_RE.finditer(text):
        url = m.group(0)
        if url not in seen:
            seen.add(url)
            result.append(url)
    return result


def count_urgency_words(text: str) -> int:
    """Count how many urgency words/phrases appear in text.

    Args:
        text: Lowercased email body text.

    Returns:
        Count of distinct urgency matches.
    """
    lower = text.lower()
    return sum(1 for w in URGENCY_WORDS if w in lower)


def count_keyword_matches(text: str) -> list[str]:
    """Return list of phishing keyword phrases found in text.

    Args:
        text: Lowercased email body text.

    Returns:
        List of matched phishing keyword phrases.
    """
    lower = text.lower()
    return [kw for kw in PHISHING_KEYWORDS if kw in lower]


def check_credential_harvest(text: str) -> list[str]:
    """Return descriptions of credential harvesting patterns found.

    Args:
        text: Email body text.

    Returns:
        List of matched pattern descriptions.
    """
    matches: list[str] = []
    for pattern in CREDENTIAL_HARVEST_PATTERNS:
        m = pattern.search(text)
        if m:
            matches.append(m.group(0))
    return matches


def analyse_urls(urls: list[str]) -> list[str]:
    """Check URLs for phishing indicators.

    Args:
        urls: List of URLs extracted from email body.

    Returns:
        List of finding descriptions.
    """
    findings: list[str] = []
    for url in urls:
        m = URL_RE.match(url)
        if not m:
            continue
        domain = m.group(1).split("/")[0].lower()

        if domain in SHORTENER_DOMAINS:
            findings.append(f"URL shortener used: {domain}")

        # IP address as domain
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain):
            findings.append(f"IP address as URL host: {domain}")

        # Homoglyph or IDN
        if re.search(r"[^\x00-\x7F]", domain):
            findings.append(f"Non-ASCII (possible homoglyph) domain: {domain}")

        # Suspicious TLD
        if re.search(r"\.(tk|ml|ga|cf|gq|xyz|top|click|link|pw|work|men)$", domain):
            findings.append(f"Suspicious TLD in URL: {domain}")

    return findings


def check_sender_anomalies(sender: str, reply_to: str) -> list[str]:
    """Check for sender/reply-to anomalies.

    Args:
        sender: From header value.
        reply_to: Reply-To header value (may be empty).

    Returns:
        List of anomaly descriptions.
    """
    findings: list[str] = []
    for pattern in SUSPICIOUS_SENDER_PATTERNS:
        if pattern.search(sender):
            findings.append(f"Suspicious sender address pattern: {sender}")
            break

    if reply_to and reply_to != sender:
        # Extract just the email parts for comparison
        sender_domain = sender.split("@")[-1].rstrip(">").lower().strip()
        reply_domain = reply_to.split("@")[-1].rstrip(">").lower().strip()
        if sender_domain != reply_domain:
            findings.append(
                f"Reply-To domain ({reply_domain}) differs from sender domain ({sender_domain})"
            )

    return findings


def check_header_anomalies(msg: EmailMessage) -> list[str]:
    """Detect header-level phishing signals.

    Args:
        msg: Parsed EmailMessage object.

    Returns:
        List of anomaly descriptions.
    """
    findings: list[str] = []

    # Missing/spoofed SPF-like indicators (we can only check structural issues)
    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        if "spf=fail" in auth_results.lower():
            findings.append("SPF check FAILED in Authentication-Results header")
        if "dkim=fail" in auth_results.lower():
            findings.append("DKIM check FAILED in Authentication-Results header")
        if "dmarc=fail" in auth_results.lower():
            findings.append("DMARC check FAILED in Authentication-Results header")

    # Excessive X-Mailer obscuring
    x_mailer = msg.get("X-Mailer", "")
    if re.search(r"mass|bulk|blast|broadcast", x_mailer, re.IGNORECASE):
        findings.append(f"Mass-mailing software detected in X-Mailer: {x_mailer}")

    # HTML-only email (no plain text version is a common phishing signal)
    content_types = set()
    if msg.is_multipart():
        for part in msg.walk():
            content_types.add(part.get_content_type())
    else:
        content_types.add(msg.get_content_type())

    if "text/html" in content_types and "text/plain" not in content_types:
        findings.append("HTML-only email with no plain text part")

    return findings


# ---------------------------------------------------------------------------
# Main analyser
# ---------------------------------------------------------------------------

def analyse_email(raw_email: str | bytes) -> PhishingAnalysis:
    """Analyse an email for phishing indicators.

    Args:
        raw_email: Raw RFC 2822 email text or bytes.

    Returns:
        PhishingAnalysis with score, verdict, and indicators.
    """
    if isinstance(raw_email, bytes):
        msg = email.message_from_bytes(raw_email, policy=email.policy.default)
    else:
        msg = email.message_from_string(raw_email, policy=email.policy.default)

    sender = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    subject = str(msg.get("Subject", ""))

    result = PhishingAnalysis(subject=subject, sender=sender)

    # Collect body text
    body_parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    body_parts.append(payload.decode("utf-8", errors="replace"))
    else:
        payload = msg.get_payload(decode=True)
        if isinstance(payload, bytes):
            body_parts.append(payload.decode("utf-8", errors="replace"))
        elif isinstance(payload, str):
            body_parts.append(payload)

    body = "\n".join(body_parts)
    result.urls = extract_urls(body)

    # Subject analysis
    subject_lower = subject.lower()
    urgency_in_subject = sum(1 for w in URGENCY_WORDS if w in subject_lower)
    if urgency_in_subject > 0:
        result.add_indicator("urgency", f"Urgency language in subject: {subject}", weight=15)

    # Body keyword analysis
    keyword_matches = count_keyword_matches(body)
    if keyword_matches:
        sample = keyword_matches[:3]
        result.add_indicator(
            "keyword",
            f"Phishing keywords found: {', '.join(sample)}",
            weight=min(30, len(keyword_matches) * 10),
        )

    # Body urgency analysis
    urgency_count = count_urgency_words(body)
    if urgency_count >= 2:
        result.add_indicator("urgency", f"{urgency_count} urgency phrases in body", weight=10)

    # Credential harvest patterns
    for harvest_match in check_credential_harvest(body):
        result.add_indicator("credential", f"Credential harvesting pattern: {harvest_match}", weight=20)

    # URL analysis
    url_findings = analyse_urls(result.urls)
    for finding in url_findings:
        result.add_indicator("url", finding, weight=15)

    # Sender anomalies
    for finding in check_sender_anomalies(sender, reply_to):
        result.add_indicator("sender", finding, weight=20)

    # Header anomalies
    for finding in check_header_anomalies(msg):
        result.add_indicator("header", finding, weight=10)

    return result
