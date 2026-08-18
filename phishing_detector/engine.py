"""Deterministic, explainable phishing-email triage rules."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from urllib.parse import unquote, urlsplit

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

LANGUAGE_RULES: tuple[tuple[str, str, int, tuple[str, ...]], ...] = (
    (
        "credential_request",
        "Credential request",
        26,
        ("password", "verify your account", "verify account", "login now", "sign in"),
    ),
    (
        "urgency",
        "Urgency pressure",
        18,
        ("urgent", "immediately", "limited time", "within 24 hours", "act now"),
    ),
    (
        "financial",
        "Financial pressure",
        22,
        ("bank account", "wire transfer", "gift card", "payment failed", "invoice"),
    ),
    (
        "reward",
        "Unexpected reward",
        15,
        ("winner", "free money", "claim your prize", "earn reward", "reward"),
    ),
    (
        "threat",
        "Threat or consequence",
        20,
        ("account suspended", "account locked", "legal action", "final warning"),
    ),
)

SHORTENER_HOSTS = {
    "bit.ly",
    "cutt.ly",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "t.co",
    "tinyurl.com",
}
SUSPICIOUS_TLDS = {
    "click",
    "country",
    "download",
    "gq",
    "link",
    "tk",
    "top",
    "work",
    "zip",
}


@dataclass(frozen=True, slots=True)
class Indicator:
    """One weighted, human-readable signal found during analysis."""

    code: str
    title: str
    weight: int
    evidence: str


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Structured result returned by :func:`analyze_email`."""

    score: int
    severity: str
    summary: str
    indicators: tuple[Indicator, ...]
    recommendations: tuple[str, ...]
    urls_analyzed: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _quoted_phrases(phrases: list[str]) -> str:
    return ", ".join(f"“{phrase}”" for phrase in phrases)


def _language_indicators(text: str) -> list[Indicator]:
    lowered = text.casefold()
    indicators: list[Indicator] = []
    for code, title, weight, phrases in LANGUAGE_RULES:
        matches = [phrase for phrase in phrases if phrase in lowered]
        if matches:
            indicators.append(
                Indicator(
                    code=code,
                    title=title,
                    weight=weight,
                    evidence=f"Found related language: {_quoted_phrases(matches[:3])}.",
                )
            )
    return indicators


def _extract_urls(text: str) -> tuple[str, ...]:
    return tuple(
        match.group(0).rstrip(".,;:!?)]}") for match in URL_PATTERN.finditer(text)
    )


def _is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        return False
    return True


def _url_indicators(urls: tuple[str, ...]) -> list[Indicator]:
    evidence: dict[str, tuple[str, int, str]] = {}
    for url in urls:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").casefold().rstrip(".")
        if parsed.scheme.casefold() == "http":
            evidence.setdefault(
                "cleartext_http",
                ("Cleartext HTTP link", 14, "At least one link does not use HTTPS."),
            )
        if hostname and _is_ip_address(hostname):
            evidence.setdefault(
                "ip_address_host",
                (
                    "IP-address link",
                    30,
                    "A link uses an IP address instead of a named domain.",
                ),
            )
        if "xn--" in hostname:
            evidence.setdefault(
                "punycode_host",
                (
                    "Punycode domain",
                    22,
                    "A link uses internationalized-domain encoding and merits review.",
                ),
            )
        if hostname in SHORTENER_HOSTS or any(
            hostname.endswith(f".{host}") for host in SHORTENER_HOSTS
        ):
            evidence.setdefault(
                "shortened_url",
                ("Shortened URL", 16, "A URL shortener hides the final destination."),
            )
        labels = [label for label in hostname.split(".") if label]
        if len(labels) > 4:
            evidence.setdefault(
                "excessive_subdomains",
                (
                    "Excessive subdomains",
                    12,
                    "A link has more than four domain labels and may obscure "
                    "its owner.",
                ),
            )
        if labels and labels[-1] in SUSPICIOUS_TLDS:
            evidence.setdefault(
                "suspicious_tld",
                (
                    "High-risk top-level domain",
                    12,
                    f"A link uses the .{labels[-1]} top-level domain.",
                ),
            )
        if unquote(url) != url:
            evidence.setdefault(
                "encoded_url",
                ("Encoded URL", 8, "A link contains percent-encoded characters."),
            )

    return [
        Indicator(code=code, title=value[0], weight=value[1], evidence=value[2])
        for code, value in evidence.items()
    ]


def _severity(score: int) -> tuple[str, str]:
    if score >= 75:
        return "Critical", "Multiple high-confidence phishing indicators are present."
    if score >= 50:
        return (
            "High",
            "Several strong phishing indicators require careful verification.",
        )
    if score >= 25:
        return (
            "Medium",
            "The message contains signals that should be verified independently.",
        )
    return "Low", "Few rule-based phishing indicators were detected."


def _recommendations(severity: str) -> tuple[str, ...]:
    baseline = (
        "Verify the sender through a trusted channel before taking action.",
        "Open known services from a saved bookmark instead of an email link.",
    )
    if severity in {"High", "Critical"}:
        return (
            "Do not click links, open attachments, reply, or provide credentials.",
            *baseline,
            "Report the message to your security team or email provider.",
        )
    return (
        *baseline,
        "Inspect the full sender address and message headers when available.",
    )


def analyze_email(text: str) -> AnalysisResult:
    """Analyze email text without network access and return explainable signals."""

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    urls = _extract_urls(text)
    indicators = _language_indicators(text) + _url_indicators(urls)
    indicators.sort(key=lambda item: (-item.weight, item.code))
    score = min(100, sum(item.weight for item in indicators))
    severity, summary = _severity(score)
    return AnalysisResult(
        score=score,
        severity=severity,
        summary=summary,
        indicators=tuple(indicators),
        recommendations=_recommendations(severity),
        urls_analyzed=len(urls),
    )
