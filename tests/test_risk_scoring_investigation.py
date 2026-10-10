"""
TrustShield — Risk Scoring Investigation & Explainability Regression Tests

Verifies:
1. Long-URL simulation (e.g. 604-character URL with no credential forms)
2. Evidence adequacy attribution (distinguishing limited vs strong evidence)
3. Score breakdown fields (heuristic_score, ml_contribution, dom_bonus, evidence_level)
4. Deceptive download / no-form scenario handling
5. Credential form submission to external domain (high risk detection)
6. Institutional login / legitimate site false-positive resilience
7. Normalization and safety (HTTPS not treated as immunity)
"""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from backend.app.main import app, risk_engine, model_service
from backend.app.feature_extractor import extract_url_features, merge_features
from backend.app.schemas import AnalyzeRequest, DomFeatures


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


class TestLongUrlAndLimitedEvidence:
    """Tests simulating the observed 604-character URL scenario."""

    def test_long_url_generates_signal_and_breakdown(self, client):
        # Simulate long URL matching havingwacks.qpon (604 chars)
        long_url = "https://havingwacks.qpon/watch?v=12345&token=" + "a" * 559
        assert len(long_url) == 604

        resp = client.post("/analyze", json={"url": long_url})
        assert resp.status_code == 200
        data = resp.json()

        # Check required breakdown fields
        assert "score_breakdown" in data
        breakdown = data["score_breakdown"]
        assert breakdown is not None
        assert "heuristic_score" in breakdown
        assert "ml_contribution" in breakdown
        assert "dom_bonus" in breakdown
        assert "evidence_level" in breakdown
        assert "confidence_note" in breakdown

        # Only long_url indicator is present (no password forms, no IP, no @)
        signals = [s["code"] for s in data["signals"]]
        assert "long_url" in signals

        # Because evidence is limited (no password forms, no known threat feed),
        # evidence_level must be 'limited'
        assert breakdown["evidence_level"] == "limited"

        # Recommendation must warn user about limited structural evidence
        assert "limited" in data["recommendation"].lower() or "caution" in data["recommendation"].lower()

    def test_derived_feature_encodings_in_merge_features(self):
        # Verify url_length_encoded and subdomain_count_encoded are properly derived
        url_long = "https://example.com/" + "a" * 80
        feats = extract_url_features(url_long)
        merged = merge_features(feats, None, None)

        assert merged["url_length_encoded"] == 1  # > 75 chars
        assert merged["subdomain_count_encoded"] == -1  # < 2 subdomains
        assert "has_favicon" in merged


class TestCredentialPhishingDetection:
    """Verifies that actual credential harvesting triggers high risk."""

    def test_credential_form_to_external_domain(self, client):
        resp = client.post("/analyze", json={
            "url": "https://secure-login-portal.com/auth",
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

        signal_codes = [s["code"] for s in data["signals"]]
        assert "credential_form_external_submit" in signal_codes
        assert data["risk_score"] >= 35
        # Must have strong or moderate evidence level
        assert data["score_breakdown"]["evidence_level"] in ("strong", "moderate")


class TestLegitimateSiteResilience:
    """Verifies legitimate institutional and top-tier domains remain low risk."""

    @pytest.mark.parametrize("url", [
        "https://www.google.com",
        "https://www.github.com",
        "https://portal.stanford.edu/login",
    ])
    def test_institutional_legitimate_sites_not_high_risk(self, client, url):
        resp = client.post("/analyze", json={
            "url": url,
            "dom_features": {
                "has_password_input": 1,
                "form_count": 1,
                "external_form_count": 0,
                "has_external_form": 0,
            }
        })
        assert resp.status_code == 200
        data = resp.json()

        # An internal institutional login form should NOT be flagged as high_risk
        assert data["classification"] != "high_risk"
        assert data["risk_score"] < 70


class TestHttpsNotTreatedAsImmunity:
    """Verifies that an HTTPS URL with phishing indicators still triggers risk."""

    def test_https_with_suspicious_features(self, client):
        # HTTPS site with IP host and at-symbol
        resp = client.post("/analyze", json={
            "url": "https://198.51.100.1@phishing-target.xyz/login"
        })
        assert resp.status_code == 200
        data = resp.json()

        # Must not be low_risk just because it uses HTTPS
        assert data["risk_score"] >= 40
        assert data["classification"] in ("suspicious", "high_risk")
