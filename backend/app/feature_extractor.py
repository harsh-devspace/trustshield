"""
TrustShield — Feature Extractor

Extracts URL-level features from a raw URL string server-side.
This mirrors the feature extraction done in background.js on the client,
providing a server-side fallback and validation layer.

The features produced here are the same set used during model training.
"""

from __future__ import annotations
import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse, unquote


import math
from collections import Counter

# TLDs frequently associated with disposable/low-cost phishing infrastructure
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".top", ".xyz", ".click", ".club", ".info",
    ".biz", ".online", ".site", ".website", ".space",
}

# Keywords that appear in phishing URLs targeting credential theft
# Note: these alone are NOT sufficient — many legitimate pages also contain them.
# The feature is used in combination with other signals, not as a standalone detector.
CREDENTIAL_KEYWORDS = [
    "login", "signin", "sign-in", "account", "verify",
    "secure", "update", "confirm", "bank", "paypal",
    "password", "credential", "auth", "authenticate",
]

# Targeted brands commonly spoofed in phishing campaigns
TARGET_BRANDS = [
    {"brand": "PayPal", "domains": ["paypal.com"]},
    {"brand": "Google", "domains": ["google.com", "accounts.google.com", "gmail.com"]},
    {"brand": "Microsoft", "domains": ["microsoft.com", "login.microsoftonline.com", "live.com", "office.com"]},
    {"brand": "Apple", "domains": ["apple.com", "icloud.com"]},
    {"brand": "Amazon", "domains": ["amazon.com", "amazon.in", "amazon.co.uk"]},
    {"brand": "Meta", "domains": ["facebook.com", "meta.com", "instagram.com", "whatsapp.com"]},
    {"brand": "Netflix", "domains": ["netflix.com"]},
    {"brand": "Banking", "domains": ["chase.com", "wellsfargo.com", "bankofamerica.com", "hdfcbank.com", "icicibank.com", "onlinesbi.sbi"]},
]

# Common Cyrillic and Greek homoglyphs impersonating Latin letters in IDN attacks
HOMOGLYPH_CHARS = {
    '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c',
    '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u03BF': 'o',
    '\u03C1': 'p', '\u03BD': 'v'
}

# Private/loopback IP ranges (simplified check — not a substitute for proper SSRF protection)
_IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def calculate_shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string in bits per symbol."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def detect_idn_homoglyph(hostname: str) -> bool:
    """Detect whether hostname uses Punycode (xn--) or Cyrillic/Greek homoglyphs."""
    if not hostname:
        return False
    hostname_lower = hostname.lower()
    if hostname_lower.startswith("xn--") or ".xn--" in hostname_lower:
        return True
    return any(char in hostname_lower for char in HOMOGLYPH_CHARS)


def detect_brand_impersonation(hostname: str) -> tuple[bool, Optional[str]]:
    """
    Detect whether an unauthorized hostname contains trademarked brand names.
    Returns (is_impersonation, brand_name).
    """
    if not hostname:
        return False, None
    hostname_lower = hostname.lower()
    for brand_info in TARGET_BRANDS:
        brand_key = brand_info["brand"].lower()
        if brand_key in hostname_lower:
            is_verified = any(
                hostname_lower == legit or hostname_lower.endswith("." + legit)
                for legit in brand_info["domains"]
            )
            if not is_verified:
                return True, brand_info["brand"]
    return False, None


def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extract a fixed set of URL structural features from a raw URL string.

    Returns a dict with the same keys used during model training.
    All values are numeric (int or float) to be compatible with scikit-learn.

    Raises ValueError if the URL cannot be parsed.
    """
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValueError(f"Cannot parse URL: {e}")

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = url

    # Subdomain count: parts beyond the registrable domain
    # Simplified: count hostname segments - 2
    parts = hostname.split(".")
    subdomain_count = max(0, len(parts) - 2)

    # Check for IP-based hostname
    has_ip_host = int(bool(_IP_PATTERN.match(hostname)))

    # Has @ in URL (phishing trick: user:pass@evil.com/legit-looking-path)
    has_at_symbol = int("@" in full_url)

    # Double slash after protocol (possible redirect obfuscation)
    after_scheme = full_url[len(parsed.scheme) + 3:]  # strip "scheme://"
    has_double_slash = int("//" in after_scheme)

    # HTTPS
    is_https = int(parsed.scheme == "https")

    # Dash in hostname
    dash_in_hostname = int("-" in hostname)

    # Dot count in full URL
    dot_count = full_url.count(".")

    # Suspicious keywords
    url_lower = full_url.lower()
    has_suspicious_keywords = int(any(kw in url_lower for kw in CREDENTIAL_KEYWORDS))

    # TLD check
    hostname_lower = hostname.lower()
    has_suspicious_tld = int(any(hostname_lower.endswith(tld) for tld in SUSPICIOUS_TLDS))

    # URL / path / query lengths
    url_length = len(full_url)
    path_length = len(path)
    query_length = len(query)

    # Non-standard port
    has_port = int(bool(parsed.port))

    # Special characters in URL (excluding common URL chars)
    special_chars = re.findall(r'[!@$%^&*()_+=\[\]{}|;\'",<>?\\]', full_url)
    special_char_count = len(special_chars)

    # Slash count in path
    slash_count = path.count("/")

    # URL encoding present
    has_encoding = int("%" in full_url)

    # Forensic telemetry features
    hostname_entropy = calculate_shannon_entropy(hostname)
    has_homoglyph = int(detect_idn_homoglyph(hostname))
    is_impersonating, impersonated_brand = detect_brand_impersonation(hostname)
    has_brand_impersonation = int(is_impersonating)

    return {
        "url_length":               url_length,
        "hostname_length":          len(hostname),
        "subdomain_count":          subdomain_count,
        "is_https":                 is_https,
        "has_ip_host":              has_ip_host,
        "has_at_symbol":            has_at_symbol,
        "has_double_slash":         has_double_slash,
        "dash_in_hostname":         dash_in_hostname,
        "dot_count":                dot_count,
        "has_suspicious_keywords":  has_suspicious_keywords,
        "path_length":              path_length,
        "query_length":             query_length,
        "has_port":                 has_port,
        "has_suspicious_tld":       has_suspicious_tld,
        "special_char_count":       special_char_count,
        "slash_count":              slash_count,
        "has_encoding":             has_encoding,
        "hostname_entropy":         hostname_entropy,
        "has_homoglyph":            has_homoglyph,
        "has_brand_impersonation":  has_brand_impersonation,
        "impersonated_brand":       impersonated_brand or "",
    }


def merge_features(
    server_features: Dict[str, Any],
    client_url_features: Optional[Dict[str, Any]],
    dom_features: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Merge server-extracted features with client-provided features.
    Server-extracted values are used as the canonical source for URL features
    (client values are used as supplementary signals only).
    DOM features are appended as additional columns.
    """
    merged = dict(server_features)

    # Derived encodings expected by the trained ML model schema
    url_len = server_features.get("url_length", 0) or 0
    if url_len > 75:
        merged["url_length_encoded"] = 1
    elif url_len >= 54:
        merged["url_length_encoded"] = 0
    else:
        merged["url_length_encoded"] = -1

    subdomains = server_features.get("subdomain_count", 0) or 0
    if subdomains > 2:
        merged["subdomain_count_encoded"] = 1
    elif subdomains == 2:
        merged["subdomain_count_encoded"] = 0
    else:
        merged["subdomain_count_encoded"] = -1

    # DOM features
    if dom_features:
        merged.update({
            "has_password_input":   dom_features.get("has_password_input", 0) or 0,
            "has_payment_input":    dom_features.get("has_payment_input", 0) or 0,
            "payment_input_count":  dom_features.get("payment_input_count", 0) or 0,
            "form_count":           dom_features.get("form_count", 0) or 0,
            "external_form_count":  dom_features.get("external_form_count", 0) or 0,
            "has_external_form":    dom_features.get("has_external_form", 0) or 0,
            "external_iframe_count": dom_features.get("external_iframe_count", 0) or 0,
            "has_favicon":          dom_features.get("has_favicon", 0) or 0,
        })
    else:
        merged.update({
            "has_password_input":   0,
            "has_payment_input":    0,
            "payment_input_count":  0,
            "form_count":           0,
            "external_form_count":  0,
            "has_external_form":    0,
            "external_iframe_count": 0,
            "has_favicon":          0,
        })

    return merged
