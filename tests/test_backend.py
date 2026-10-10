"""
TrustShield — Backend Test Suite

Tests cover:
- Health endpoint
- Valid analysis requests
- Invalid input handling
- Risk-score boundary validation
- Classification threshold correctness
- SSRF/private-IP protection
- Missing model artifact handling
- Signal schema validation
- False-positive tests (legitimate sites)

Run with: pytest tests/test_backend.py -v
"""

import sys
import os
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

# Add the backend to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from backend.app.main import app, model_service, risk_engine
from backend.app.schemas import AnalyzeRequest, UrlFeatures, DomFeatures
from backend.app.feature_extractor import extract_url_features
from backend.app.risk_engine import RiskEngine, THRESHOLDS


# ─── Test client ──────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ─── Health endpoint ───────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_has_required_fields(self, client):
        data = client.get("/health").json()
        assert "status" in data
        assert "model_loaded" in data
        assert "version" in data

    def test_health_status_value(self, client):
        data = client.get("/health").json()
        assert data["status"] in ("ok", "degraded")

    def test_health_model_loaded_is_bool(self, client):
        data = client.get("/health").json()
        assert isinstance(data["model_loaded"], bool)


# ─── Analyze endpoint — valid requests ────────────────────────────────────────

class TestAnalyzeValid:
    def test_valid_https_url(self, client):
        response = client.post("/analyze", json={"url": "https://www.google.com"})
        assert response.status_code == 200

    def test_response_has_required_fields(self, client):
        data = client.post("/analyze", json={"url": "https://www.example.com"}).json()
        assert "url_host" in data
        assert "risk_score" in data
        assert "classification" in data
        assert "signals" in data
        assert "recommendation" in data
        assert "model_available" in data

    def test_risk_score_in_range(self, client):
        data = client.post("/analyze", json={"url": "https://www.github.com"}).json()
        assert 0 <= data["risk_score"] <= 100

    def test_classification_valid_value(self, client):
        data = client.post("/analyze", json={"url": "https://www.example.com"}).json()
        assert data["classification"] in ("low_risk", "suspicious", "high_risk")

    def test_url_host_matches_input(self, client):
        data = client.post("/analyze", json={"url": "https://www.example.com"}).json()
        assert "example.com" in data["url_host"]

    def test_signals_is_list(self, client):
        data = client.post("/analyze", json={"url": "https://www.example.com"}).json()
        assert isinstance(data["signals"], list)

    def test_signal_has_required_fields(self, client):
        # Use a URL likely to generate at least one signal (HTTP = no_https signal)
        data = client.post("/analyze", json={"url": "http://phishing-test.tk/login"}).json()
        assert "signals" in data
        for signal in data["signals"]:
            assert "code" in signal
            assert "severity" in signal
            assert "description" in signal
            assert signal["severity"] in ("high", "medium", "low")

    def test_recommendation_is_nonempty_string(self, client):
        data = client.post("/analyze", json={"url": "https://www.example.com"}).json()
        assert isinstance(data["recommendation"], str)
        assert len(data["recommendation"]) > 0

    def test_with_url_features(self, client):
        response = client.post("/analyze", json={
            "url": "https://www.example.com",
            "url_features": {
                "url_length": 23,
                "hostname_length": 11,
                "subdomain_count": 0,
                "is_https": 1,
                "has_ip_host": 0,
                "has_at_symbol": 0,
            }
        })
        assert response.status_code == 200

    def test_with_dom_features(self, client):
        response = client.post("/analyze", json={
            "url": "https://www.example.com",
            "dom_features": {
                "has_password_input": 0,
                "form_count": 1,
                "external_form_count": 0,
                "has_external_form": 0,
            }
        })
        assert response.status_code == 200

    def test_http_url_gets_no_https_signal(self, client):
        data = client.post("/analyze", json={"url": "http://www.example.com"}).json()
        signal_codes = [s["code"] for s in data["signals"]]
        assert "no_https" in signal_codes

    def test_ip_host_gets_high_risk_signal(self, client):
        # Use a public IP (not private/loopback) to avoid SSRF block
        data = client.post("/analyze", json={"url": "http://203.0.113.5/login"}).json()
        signal_codes = [s["code"] for s in data["signals"]]
        assert "ip_based_host" in signal_codes

    def test_at_symbol_url_gets_signal(self, client):
        data = client.post("/analyze", json={"url": "http://evil.com@legit-looking.com/"}).json()
        signal_codes = [s["code"] for s in data["signals"]]
        assert "at_symbol_in_url" in signal_codes


# ─── Invalid input handling ────────────────────────────────────────────────────

class TestAnalyzeInvalidInput:
    def test_missing_url_field(self, client):
        response = client.post("/analyze", json={})
        assert response.status_code == 422

    def test_empty_url(self, client):
        response = client.post("/analyze", json={"url": ""})
        assert response.status_code == 422

    def test_non_http_url(self, client):
        response = client.post("/analyze", json={"url": "ftp://example.com"})
        assert response.status_code == 422

    def test_chrome_url_rejected(self, client):
        response = client.post("/analyze", json={"url": "chrome://settings"})
        assert response.status_code == 422

    def test_url_too_long(self, client):
        long_url = "https://example.com/" + "a" * 2100
        response = client.post("/analyze", json={"url": long_url})
        assert response.status_code == 422

    def test_malformed_json(self, client):
        response = client.post(
            "/analyze",
            data="not-json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422

    def test_invalid_url_format(self, client):
        response = client.post("/analyze", json={"url": "not a url at all"})
        assert response.status_code == 422


# ─── SSRF protection ──────────────────────────────────────────────────────────

class TestSSRFProtection:
    def test_localhost_blocked(self, client):
        response = client.post("/analyze", json={"url": "http://localhost/admin"})
        assert response.status_code == 422

    def test_loopback_ip_blocked(self, client):
        response = client.post("/analyze", json={"url": "http://127.0.0.1/secret"})
        assert response.status_code == 422

    def test_metadata_endpoint_blocked(self, client):
        response = client.post("/analyze", json={"url": "http://169.254.169.254/metadata"})
        assert response.status_code == 422

    def test_private_ip_blocked(self, client):
        response = client.post("/analyze", json={"url": "http://10.0.0.1/internal"})
        assert response.status_code == 422


# ─── Risk score boundaries ─────────────────────────────────────────────────────

class TestRiskScoreBoundaries:
    def test_score_never_below_zero(self, client):
        # Clean URL should not produce negative score
        data = client.post("/analyze", json={"url": "https://www.gov.uk"}).json()
        assert data["risk_score"] >= 0

    def test_score_never_above_100(self, client):
        # Worst-case URL should not exceed 100
        data = client.post("/analyze", json={"url": "http://192.0.2.1@evil.tk/login?user=admin"}).json()
        assert data["risk_score"] <= 100


# ─── Classification thresholds ────────────────────────────────────────────────

class TestClassificationThresholds:
    def test_high_risk_threshold(self):
        assert THRESHOLDS["high_risk"] == 70

    def test_suspicious_threshold(self):
        assert THRESHOLDS["suspicious"] == 40

    def test_risk_engine_classifies_correctly(self):
        # Mocked model service that's unavailable
        mock_ms = MagicMock()
        mock_ms.predict.return_value = None
        mock_ms.is_loaded.return_value = False

        engine = RiskEngine(model_service=mock_ms)

        # IP-based URL with @ and suspicious TLD — multiple high signals
        # At-symbol (28) + no_https (14) + suspicious_tld (20) + ip_with_keywords compound = > 40 (suspicious at minimum)
        result = engine.analyze("http://203.0.113.5@phishing.tk/login?user=admin")
        # With at_symbol (28) + no_https (14) + suspicious_tld (20) = 62 + possible ip_with_keywords = > suspicious
        assert result.classification in ("suspicious", "high_risk")
        assert result.risk_score >= THRESHOLDS["suspicious"]

    def test_clean_url_low_risk(self):
        mock_ms = MagicMock()
        mock_ms.predict.return_value = None
        mock_ms.is_loaded.return_value = False

        engine = RiskEngine(model_service=mock_ms)
        result = engine.analyze("https://www.google.com")
        assert result.classification in ("low_risk", "suspicious")


# ─── False-positive tests (legitimate sites) ──────────────────────────────────

class TestFalsePositives:
    """Verify that well-known legitimate sites don't get flagged as high risk."""

    @pytest.mark.parametrize("url", [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.microsoft.com",
        "https://stackoverflow.com",
        "https://www.bbc.co.uk",
    ])
    def test_known_safe_not_high_risk(self, client, url):
        data = client.post("/analyze", json={"url": url}).json()
        # Should not be flagged as high risk without ML (heuristics only)
        # Some may be suspicious due to heuristics — that's OK
        # But these should NOT be high_risk (score < 70) without ML
        assert data["risk_score"] < 70, f"{url} was flagged as high risk (score={data['risk_score']})"


# ─── Feature extractor tests ──────────────────────────────────────────────────

class TestFeatureExtractor:
    def test_https_url(self):
        features = extract_url_features("https://www.example.com")
        assert features["is_https"] == 1

    def test_http_url(self):
        features = extract_url_features("http://www.example.com")
        assert features["is_https"] == 0

    def test_ip_host_detection(self):
        features = extract_url_features("http://192.168.1.1/")
        assert features["has_ip_host"] == 1

    def test_at_symbol_detection(self):
        features = extract_url_features("http://user@evil.com/")
        assert features["has_at_symbol"] == 1

    def test_normal_url_no_flags(self):
        features = extract_url_features("https://www.example.com/page")
        assert features["has_ip_host"] == 0
        assert features["has_at_symbol"] == 0

    def test_feature_count(self):
        features = extract_url_features("https://www.example.com")
        # Should return all expected features
        expected_keys = [
            "url_length", "hostname_length", "subdomain_count", "is_https",
            "has_ip_host", "has_at_symbol", "has_double_slash", "dash_in_hostname",
            "dot_count", "has_suspicious_keywords", "path_length", "query_length",
            "has_port", "has_suspicious_tld", "special_char_count", "slash_count",
            "has_encoding",
        ]
        for key in expected_keys:
            assert key in features, f"Missing feature: {key}"


# ─── Model info endpoint ───────────────────────────────────────────────────────

class TestModelInfoEndpoint:
    def test_model_info_returns_200(self, client):
        response = client.get("/model-info")
        assert response.status_code == 200

    def test_model_info_has_required_fields(self, client):
        data = client.get("/model-info").json()
        assert "model_type" in data
        assert "model_available" in data
        assert "features" in data
        assert "training_dataset" in data
        assert "evaluation_metrics" in data

    def test_features_is_list(self, client):
        data = client.get("/model-info").json()
        assert isinstance(data["features"], list)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
