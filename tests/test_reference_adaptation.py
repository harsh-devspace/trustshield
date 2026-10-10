"""
TrustShield — Reference Adaptation Tests
Validates functionality adapted from the reference repository:
- Shannon Entropy calculation and DGA detection
- IDN Homograph and Cyrillic/Greek homoglyph detection
- Brand Impersonation and typosquatting detection
- Payment card form harvesting detection
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from backend.app.feature_extractor import (
    calculate_shannon_entropy,
    detect_idn_homoglyph,
    detect_brand_impersonation,
    extract_url_features,
    merge_features,
)
from backend.app.risk_engine import RiskEngine
from backend.app.model_service import ModelService
from backend.app.schemas import UrlFeatures, DomFeatures


@pytest.fixture
def risk_engine():
    service = ModelService()
    service.load_model()
    return RiskEngine(service)


class TestEntropyAndHomoglyph:
    def test_shannon_entropy_calculation(self):
        # Repetitive string has low entropy
        low_ent = calculate_shannon_entropy("aaaaaaaa")
        assert low_ent == 0.0

        # Uniform high-randomness string
        high_ent = calculate_shannon_entropy("q1w2e3r4t5y6u7i8o9p0")
        assert high_ent > 4.0

        # Standard domain
        domain_ent = calculate_shannon_entropy("google.com")
        assert 2.0 < domain_ent < 3.5

    def test_idn_homoglyph_punycode_detection(self):
        # Punycode domain
        assert detect_idn_homoglyph("xn--pple-43d.com") is True
        assert detect_idn_homoglyph("login.xn--gogle-pra.com") is True

        # Cyrillic 'a' (\u0430) spoofing 'apple.com'
        cyrillic_apple = "\u0430pple.com"
        assert detect_idn_homoglyph(cyrillic_apple) is True

        # Legitimate Latin domain
        assert detect_idn_homoglyph("apple.com") is False
        assert detect_idn_homoglyph("github.com") is False

    def test_brand_impersonation_detection(self):
        # Unauthorized domain containing PayPal
        is_spoof, brand = detect_brand_impersonation("paypal-account-verify.net")
        assert is_spoof is True
        assert brand == "PayPal"

        # Legitimate brand domain
        is_spoof, brand = detect_brand_impersonation("paypal.com")
        assert is_spoof is False
        assert brand is None

        # Legitimate subdomain
        is_spoof, brand = detect_brand_impersonation("accounts.google.com")
        assert is_spoof is False

        # Fake Google portal
        is_spoof, brand = detect_brand_impersonation("google-security-login.xyz")
        assert is_spoof is True
        assert brand == "Google"


class TestIntegratedRiskDetection:
    def test_homoglyph_triggers_high_risk_signal(self, risk_engine):
        url = "https://\u0430pple.com/verify-account"
        response = risk_engine.analyze(url)
        signal_codes = [s.code for s in response.signals]
        assert "idn_homoglyph_spoof" in signal_codes
        assert response.risk_score >= 40

    def test_brand_impersonation_triggers_signal(self, risk_engine):
        url = "https://paypal-security-update.com/signin"
        response = risk_engine.analyze(url)
        signal_codes = [s.code for s in response.signals]
        assert "brand_impersonation" in signal_codes
        assert response.risk_score >= 40

    def test_payment_harvesting_external_form(self, risk_engine):
        url = "https://checkout-secure-flow.com/pay"
        dom = DomFeatures(
            has_payment_input=1,
            payment_input_count=2,
            has_external_form=1,
            external_form_count=1,
        )
        response = risk_engine.analyze(url, dom_features=dom)
        signal_codes = [s.code for s in response.signals]
        assert "payment_form_external_submit" in signal_codes
        assert response.risk_score >= 40

    def test_score_breakdown_contains_forensic_telemetry(self, risk_engine):
        url = "https://paypal-security-update.com/signin"
        response = risk_engine.analyze(url)
        assert response.score_breakdown is not None
        assert response.score_breakdown.entropy is not None
        assert response.score_breakdown.brand_impersonation == "PayPal"
