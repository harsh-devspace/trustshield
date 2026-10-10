"""
TrustShield — Comprehensive Audit & Realistic Fixture Test Suite

Tests empirical behavior across 12 distinct categories:
1. Legitimate high-traffic URLs
2. Long but legitimate institutional / cloud URLs
3. Suspicious structural URL patterns (IP, @ symbol, double slash)
4. Lookalike & deceptive hostname patterns
5. URL percent-encoded redirection strings
6. Credential forms submitting to external domains
7. Controlled redirect obfuscation fixtures
8. Benign institutional & educational login pages
9. Malformed, oversized, and SSRF-restricted inputs
10. Model service degradation & offline fallback
11. Unknown / inconclusive domain evaluation (limited evidence)
12. Optional Threat Intelligence mock match & graceful error handling
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from backend.app.main import app, risk_engine, model_service, threat_intel_service
from backend.app.schemas import AnalyzeRequest
from backend.app.risk_engine import RiskEngine, THRESHOLDS
from backend.app.threat_intel import ThreatIntelService


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


class TestRealisticFixtures:

    # 1. Legitimate high-traffic URLs
    @pytest.mark.parametrize("url", [
        "https://www.google.com",
        "https://www.github.com",
        "https://en.wikipedia.org/wiki/Computer_security",
    ])
    def test_legitimate_urls_low_risk(self, client, url):
        resp = client.post("/analyze", json={"url": url})
        assert resp.status_code == 200
        data = resp.json()
        assert data["classification"] == "low_risk"
        assert data["risk_score"] < 40

    # 2. Long but legitimate institutional/cloud URLs
    def test_long_legitimate_cloud_url(self, client):
        long_legit_url = "https://aws.amazon.com/console/home?region=us-east-1&state=" + "x" * 150
        resp = client.post("/analyze", json={"url": long_legit_url})
        assert resp.status_code == 200
        data = resp.json()
        # Even with long_url signal, it must remain low risk (not marked suspicious or high risk)
        assert data["risk_score"] < 40
        assert data["classification"] == "low_risk"

    # 3. Suspicious structural URL patterns
    def test_ip_based_url(self, client):
        resp = client.post("/analyze", json={"url": "http://198.51.100.25/login"})
        assert resp.status_code == 200
        data = resp.json()
        signals = [s["code"] for s in data["signals"]]
        assert "ip_based_host" in signals
        assert data["risk_score"] >= 35

    def test_at_symbol_credential_trick(self, client):
        resp = client.post("/analyze", json={"url": "https://legit-brand.com@evil-destination.com/account"})
        assert resp.status_code == 200
        data = resp.json()
        signals = [s["code"] for s in data["signals"]]
        assert "at_symbol_in_url" in signals
        assert data["risk_score"] >= 28

    def test_double_slash_redirect_pattern(self, client):
        resp = client.post("/analyze", json={"url": "https://example.com//redirect//login"})
        assert resp.status_code == 200
        data = resp.json()
        signals = [s["code"] for s in data["signals"]]
        assert "double_slash_redirect" in signals

    # 4. Lookalike & deceptive hostname patterns
    def test_lookalike_tld_and_keywords(self, client):
        resp = client.post("/analyze", json={"url": "http://paypal-verification-account.xyz/update"})
        assert resp.status_code == 200
        data = resp.json()
        signals = [s["code"] for s in data["signals"]]
        assert "suspicious_tld" in signals
        assert data["classification"] in ("suspicious", "high_risk")

    # 5. URL percent-encoded strings
    def test_percent_encoded_url(self, client):
        resp = client.post("/analyze", json={"url": "https://example.com/auth%20session%2Ftoken"})
        assert resp.status_code == 200
        data = resp.json()
        signals = [s["code"] for s in data["signals"]]
        assert "url_encoding" in signals

    # 6. Credential form submitting to external destination
    def test_external_credential_submission(self, client):
        resp = client.post("/analyze", json={
            "url": "https://my-company-intranet.com/login",
            "dom_features": {
                "has_password_input": 1,
                "password_input_count": 1,
                "form_count": 1,
                "external_form_count": 1,
                "has_external_form": 1,
            }
        })
        assert resp.status_code == 200
        data = resp.json()
        signals = [s["code"] for s in data["signals"]]
        assert "credential_form_external_submit" in signals
        assert data["risk_score"] >= 35

    # 7. Benign institutional & educational login pages
    @pytest.mark.parametrize("url", [
        "https://login.mit.edu/cas/login",
        "https://portal.ox.ac.uk/auth",
        "https://my.harvard.edu",
    ])
    def test_institutional_logins_not_flagged(self, client, url):
        # A legitimate institution with an internal password form must not be flagged
        resp = client.post("/analyze", json={
            "url": url,
            "dom_features": {
                "has_password_input": 1,
                "password_input_count": 1,
                "form_count": 1,
                "external_form_count": 0,
                "has_external_form": 0,
            }
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["classification"] != "high_risk"
        assert data["risk_score"] < 70

    # 8. Malformed, oversized, and SSRF inputs
    def test_empty_url_rejected(self, client):
        resp = client.post("/analyze", json={"url": ""})
        assert resp.status_code == 422

    def test_non_http_rejected(self, client):
        resp = client.post("/analyze", json={"url": "javascript:alert(1)"})
        assert resp.status_code == 422

    def test_oversized_url_rejected(self, client):
        oversized = "https://example.com/" + "a" * 2100
        resp = client.post("/analyze", json={"url": oversized})
        assert resp.status_code == 422

    def test_ssrf_private_ip_rejected(self, client):
        resp = client.post("/analyze", json={"url": "http://192.168.1.1/"})
        assert resp.status_code == 422

    def test_ssrf_cloud_metadata_rejected(self, client):
        resp = client.post("/analyze", json={"url": "http://169.254.169.254/latest/meta-data/"})
        assert resp.status_code == 422

    # 9. Model service offline fallback
    def test_model_unavailable_fallback_to_heuristics(self):
        mock_ms = MagicMock()
        mock_ms.predict.return_value = None
        mock_ms.is_loaded.return_value = False

        engine = RiskEngine(model_service=mock_ms)
        # Should gracefully return without crashing
        res = engine.analyze("https://havingwacks.qpon/watch?v=123")
        assert res.model_available is False
        assert 0 <= res.risk_score <= 100

    # 10. Unknown / inconclusive domain evaluation
    def test_unknown_domain_reports_limited_evidence(self, client):
        resp = client.post("/analyze", json={"url": "https://havingwacks.qpon/watch?v=123"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["score_breakdown"]["evidence_level"] == "limited"
        assert "limited" in data["score_breakdown"]["confidence_note"].lower()

    # 11. Threat Intelligence Mock Matches
    def test_threat_intel_match_elevates_to_high_risk(self):
        mock_ms = MagicMock()
        mock_ms.predict.return_value = {"phishing_probability": 0.1, "predicted_class": 0}
        mock_ms.is_loaded.return_value = True

        mock_ti = MagicMock(spec=ThreatIntelService)
        mock_ti.is_configured.return_value = True
        mock_ti.check_url.return_value = {
            "checked": True,
            "is_threat": True,
            "threat_type": "SOCIAL_ENGINEERING",
            "provider": "google_safe_browsing",
            "details": "Confirmed phishing threat.",
        }

        engine = RiskEngine(model_service=mock_ms, threat_intel=mock_ti)
        result = engine.analyze("https://legit-looking-domain.com/login")
        assert result.risk_score >= 90
        assert result.classification == "high_risk"
        signals = [s.code for s in result.signals]
        assert "threat_intel_confirmed_match" in signals

    def test_threat_intel_offline_graceful_fallback(self):
        mock_ms = MagicMock()
        mock_ms.predict.return_value = {"phishing_probability": 0.05, "predicted_class": 0}
        mock_ms.is_loaded.return_value = True

        mock_ti = MagicMock(spec=ThreatIntelService)
        mock_ti.is_configured.return_value = True
        mock_ti.check_url.return_value = {
            "checked": False,
            "is_threat": False,
            "threat_type": None,
            "provider": "google_safe_browsing_error",
            "details": "Lookup timed out.",
        }

        engine = RiskEngine(model_service=mock_ms, threat_intel=mock_ti)
        result = engine.analyze("https://www.example.com")
        assert result.classification == "low_risk"
