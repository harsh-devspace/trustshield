"""
TrustShield — Pydantic schemas for request/response validation.
"""

from __future__ import annotations
from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, HttpUrl, Field, field_validator
import re


# ─── Inbound ─────────────────────────────────────────────────────────────────

class UrlFeatures(BaseModel):
    """Pre-extracted URL-level features from the browser extension."""
    url_length: Optional[int] = None
    hostname_length: Optional[int] = None
    subdomain_count: Optional[int] = None
    is_https: Optional[int] = None           # 0 or 1
    has_ip_host: Optional[int] = None        # 0 or 1
    has_at_symbol: Optional[int] = None      # 0 or 1
    has_double_slash: Optional[int] = None   # 0 or 1
    dash_in_hostname: Optional[int] = None   # 0 or 1
    dot_count: Optional[int] = None
    has_suspicious_keywords: Optional[int] = None  # 0 or 1
    path_length: Optional[int] = None
    query_length: Optional[int] = None
    has_port: Optional[int] = None           # 0 or 1
    has_suspicious_tld: Optional[int] = None # 0 or 1
    special_char_count: Optional[int] = None
    slash_count: Optional[int] = None
    has_encoding: Optional[int] = None       # 0 or 1


class DomFeatures(BaseModel):
    """Pre-extracted DOM structural features from the browser content script."""
    has_password_input: Optional[int] = None     # 0 or 1
    password_input_count: Optional[int] = None
    form_count: Optional[int] = None
    external_form_count: Optional[int] = None
    external_iframe_count: Optional[int] = None
    has_external_form: Optional[int] = None      # 0 or 1
    title_length: Optional[int] = None
    has_favicon: Optional[int] = None            # 0 or 1


class AnalyzeRequest(BaseModel):
    """Request body for POST /analyze"""
    url: str = Field(..., description="The full URL to analyze")
    url_features: Optional[UrlFeatures] = None
    dom_features: Optional[DomFeatures] = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL must not be empty")
        if len(v) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters")
        # Must be http or https
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("URL must begin with http:// or https://")
        # Block private/loopback addresses (SSRF protection)
        # We extract the hostname and check it
        try:
            from urllib.parse import urlparse
            parsed = urlparse(v)
            host = parsed.hostname or ""
            _block_private_hosts(host)
        except ValueError:
            raise
        except Exception:
            pass  # URL parsing errors handled elsewhere
        return v


# Networks that must be blocked for SSRF protection.
# We enumerate these explicitly rather than relying on ip.is_private, because
# Python 3.12 expanded that flag to cover documentation/test ranges (RFC 5737)
# such as 203.0.113.x, which are technically harmless to analyse as URL strings.
_SSRF_BLOCKED_NETWORKS = [
    # RFC 1918 private ranges
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    # Loopback
    "127.0.0.0/8",
    "::1/128",
    # Link-local
    "169.254.0.0/16",
    "fe80::/10",
    # Cloud metadata (AWS/GCP/Azure)
    "169.254.169.254/32",
    # Unique local (IPv6 equivalent of RFC 1918)
    "fc00::/7",
    # Multicast
    "224.0.0.0/4",
    "ff00::/8",
]

try:
    import ipaddress as _ipaddress
    _SSRF_BLOCKED = [_ipaddress.ip_network(n) for n in _SSRF_BLOCKED_NETWORKS]
except Exception:
    _SSRF_BLOCKED = []


def _block_private_hosts(host: str) -> None:
    """
    Raise ValueError if the host is a private/loopback/link-local address.
    This is a defense-in-depth SSRF check — the backend never fetches URLs.

    Uses an explicit network list rather than ip.is_private so that RFC 5737
    documentation ranges (e.g. 203.0.113.x) used in tests are not wrongly
    rejected on Python 3.12+.
    """
    import ipaddress
    # Strip IPv6 brackets
    if host.startswith("["):
        host = host[1:host.index("]")]

    blocked_hosts = {"localhost", "metadata.google.internal", "169.254.169.254"}
    if host.lower() in blocked_hosts:
        raise ValueError(f"Blocked host: {host}")

    try:
        ip = ipaddress.ip_address(host)
        for network in _SSRF_BLOCKED:
            if ip in network:
                raise ValueError(f"Private/reserved IP addresses are not permitted: {host}")
    except ValueError as e:
        if "not permitted" in str(e):
            raise
        # Not an IP address — domain name is accepted (we never resolve it)
        pass


# ─── Outbound ─────────────────────────────────────────────────────────────────

class Signal(BaseModel):
    """A single detected risk indicator."""
    code: str
    severity: Literal["high", "medium", "low"]
    description: str
    source: Literal["heuristic", "ml", "dom", "threat_intel"] = "heuristic"


class ScoreBreakdown(BaseModel):
    """Detailed attribution for the composite risk score."""
    heuristic_score: int = Field(..., description="Raw points from rule-based heuristic checks")
    ml_contribution: int = Field(..., description="Points contributed by ML phishing probability (up to 60)")
    dom_bonus: int = Field(..., description="Points contributed by structural DOM signals")
    raw_blended_score: float = Field(..., description="Unrounded blended score before clamping")
    evidence_level: Literal["limited", "moderate", "strong"] = Field(
        ...,
        description="Assessment confidence based on indicator density and signal availability"
    )
    confidence_note: str = Field(
        ...,
        description="Notice explaining evidence limits (e.g. low score does not guarantee safe software downloads)"
    )


class AnalyzeResponse(BaseModel):
    """Response body for POST /analyze"""
    url_host: str
    risk_score: int = Field(..., ge=0, le=100)
    classification: Literal["low_risk", "suspicious", "high_risk"]
    signals: List[Signal]
    recommendation: str
    model_available: bool
    score_breakdown: Optional[ScoreBreakdown] = None
    api_version: str = "1.0.0"


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    model_loaded: bool
    version: str


class ModelInfoResponse(BaseModel):
    model_type: str
    model_available: bool
    features: List[str]
    training_dataset: str
    evaluation_metrics: Dict[str, Any]
    trained_at: Optional[str] = None
    notes: str
