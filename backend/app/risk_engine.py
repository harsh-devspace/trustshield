"""
TrustShield — Risk Engine

Combines URL heuristics, DOM signals, and ML predictions into a single
explainable risk score with evidence-based classification.

Scoring methodology:
  - High-confidence heuristic indicators contribute directly to the score.
  - ML prediction contributes a weighted probability component.
  - DOM signals can increase the score when credential-stealing behavior is detected.
  - Known-threat matches (if a threat intel provider is available) override ML scores.
  - Score thresholds are configurable and documented below.

Classification thresholds (configurable via THRESHOLDS):
  - 0–39:  low_risk
  - 40–69: suspicious
  - 70–100: high_risk
"""

from __future__ import annotations
import logging
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from .schemas import AnalyzeResponse, Signal, ScoreBreakdown
from .feature_extractor import extract_url_features, merge_features
from .model_service import ModelService

logger = logging.getLogger("trustshield.risk_engine")

# ─── Thresholds ────────────────────────────────────────────────────────────────
THRESHOLDS = {
    "high_risk":    70,   # Score >= 70 → high_risk
    "suspicious":   40,   # Score >= 40 → suspicious; below → low_risk
}

# ─── Heuristic weights ─────────────────────────────────────────────────────────
# Each heuristic contributes a fixed number of points to the local score.
# Weights were chosen to minimize false positives on legitimate institutional pages.
HEURISTIC_WEIGHTS = {
    "ip_based_host":             35,   # Very strong indicator
    "at_symbol_in_url":          28,   # Strong phishing technique
    "double_slash_redirect":     15,
    "excessive_subdomains":      18,   # > 3 subdomains
    "no_https":                  14,
    "suspicious_tld":            20,
    "long_url":                  8,    # > 100 chars
    "url_encoding":              5,
    "ip_with_keywords":          22,   # IP + credential keyword combo
}


class RiskEngine:
    """
    Orchestrates the complete risk analysis pipeline.
    """

    def __init__(self, model_service: ModelService, threat_intel: Optional[Any] = None):
        self.model_service = model_service
        self.threat_intel = threat_intel

    def analyze(
        self,
        url: str,
        url_features: Optional[Any] = None,
        dom_features: Optional[Any] = None,
    ) -> AnalyzeResponse:
        """
        Run full risk analysis for a URL.

        Args:
            url: The full URL string to analyze.
            url_features: Pre-extracted URL features from the browser (UrlFeatures model).
            dom_features: Pre-extracted DOM structural features (DomFeatures model).

        Returns:
            AnalyzeResponse with risk score, classification, signals, and recommendation.

        Raises:
            ValueError: If the URL is malformed or cannot be parsed.
        """
        # Parse URL
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
        except Exception as e:
            raise ValueError(f"Invalid URL: {e}")

        if not hostname:
            raise ValueError("URL has no resolvable hostname")

        # ─── Step 1: Extract features server-side ─────────────────────────────
        server_features = extract_url_features(url)

        # Convert Pydantic models to dicts if provided
        url_feat_dict = url_features.model_dump() if url_features else None
        dom_feat_dict = dom_features.model_dump() if dom_features else None

        # Merge features (server-extracted URL features are canonical)
        all_features = merge_features(server_features, url_feat_dict, dom_feat_dict)

        # ─── Step 2: Local heuristic analysis ────────────────────────────────
        heuristic_signals, heuristic_score = self._heuristic_analysis(
            url, parsed, server_features
        )

        # ─── Step 3: DOM signal analysis ──────────────────────────────────────
        dom_signals, dom_score_bonus = self._dom_analysis(dom_feat_dict or {})

        # ─── Step 3.5: Optional Threat Intelligence Lookup ────────────────────
        ti_signals = []
        if self.threat_intel and self.threat_intel.is_configured():
            ti_result = self.threat_intel.check_url(url)
            if ti_result.get("is_threat"):
                threat_type = ti_result.get("threat_type", "MALICIOUS")
                ti_signals.append(Signal(
                    code="threat_intel_confirmed_match",
                    severity="high",
                    description=f"Confirmed threat match in {ti_result.get('provider')}: {ti_result.get('details')}",
                    source="threat_intel",
                ))

        # ─── Step 4: ML prediction ────────────────────────────────────────────
        ml_signals = []
        ml_score_contribution = 0
        model_available = False

        ml_result = self.model_service.predict(all_features)
        if ml_result is not None:
            model_available = True
            phishing_prob = ml_result["phishing_probability"]

            # ML contributes up to 60 points to the final score
            ml_score_contribution = round(phishing_prob * 60)

            if phishing_prob >= 0.7:
                ml_signals.append(Signal(
                    code="ml_phishing_prediction",
                    severity="high",
                    description=f"The ML model predicts a {phishing_prob:.0%} probability of phishing.",
                    source="ml",
                ))
            elif phishing_prob >= 0.45:
                ml_signals.append(Signal(
                    code="ml_uncertain",
                    severity="medium",
                    description=f"The ML model is uncertain ({phishing_prob:.0%} phishing probability). Other signals should guide this assessment.",
                    source="ml",
                ))
            # Low ML score alone does not produce a signal (avoids false reassurance)

        # ─── Step 5: Combine scores ────────────────────────────────────────────
        if ti_signals:
            # Confirmed blacklist / threat feed match overrides local score
            raw_score = 95
        elif model_available:
            # Weighted combination: heuristic has 40% weight, ML has 60%
            # High-confidence heuristics or accumulated suspicious signals dominate
            has_strong_heuristic = (
                any(s.severity == "high" for s in heuristic_signals + dom_signals) or
                (heuristic_score + dom_score_bonus) >= THRESHOLDS["suspicious"]
            )

            if has_strong_heuristic:
                # Strong heuristic evidence: take max of heuristic-led and ML-led scores
                heuristic_led = min(heuristic_score + dom_score_bonus, 100)
                ml_led = min(ml_score_contribution + (heuristic_score * 0.2) + dom_score_bonus, 100)
                raw_score = max(heuristic_led, ml_led)
            else:
                # Normal blend: 40% heuristic, 60% ML
                raw_score = (
                    0.4 * (heuristic_score + dom_score_bonus) +
                    0.6 * (ml_score_contribution + dom_score_bonus * 0.5)
                )
        else:
            # Heuristics only
            raw_score = min(heuristic_score + dom_score_bonus, 100)

        final_score = max(0, min(100, round(raw_score)))

        # ─── Step 6: Determine classification ─────────────────────────────────
        if final_score >= THRESHOLDS["high_risk"]:
            classification = "high_risk"
        elif final_score >= THRESHOLDS["suspicious"]:
            classification = "suspicious"
        else:
            classification = "low_risk"

        # ─── Step 7: Build signal list ────────────────────────────────────────
        # Sort: high → medium → low
        all_signals = ti_signals + heuristic_signals + dom_signals + ml_signals
        severity_order = {"high": 0, "medium": 1, "low": 2}
        all_signals.sort(key=lambda s: severity_order.get(s.severity, 2))

        # ─── Step 8: Evidence level & Explainability breakdown ────────────────
        has_high_sev = any(s.severity == "high" for s in all_signals)
        has_med_sev = any(s.severity == "medium" for s in all_signals)
        ml_prob = ml_result["phishing_probability"] if ml_result else 0.0

        if has_high_sev or ml_prob >= 0.70:
            evidence_level = "strong"
            confidence_note = "High-confidence structural threat indicators were detected."
        elif has_med_sev or ml_prob >= 0.40 or len(all_signals) >= 2:
            evidence_level = "moderate"
            confidence_note = "Moderate evidence available based on detected structural signals and model evaluation."
        else:
            evidence_level = "limited"
            confidence_note = (
                "Assessment is based on limited structural indicators. No credential-harvesting forms were detected; "
                "note that this score does not certify the page safe from deceptive downloads, malvertising, or social engineering."
            )

        score_breakdown = ScoreBreakdown(
            heuristic_score=heuristic_score,
            ml_contribution=ml_score_contribution,
            dom_bonus=dom_score_bonus,
            raw_blended_score=round(float(raw_score), 2),
            evidence_level=evidence_level,
            confidence_note=confidence_note,
        )

        # ─── Step 9: Recommendation ───────────────────────────────────────────
        recommendation = self._build_recommendation(classification, all_signals, evidence_level)

        return AnalyzeResponse(
            url_host=hostname,
            risk_score=final_score,
            classification=classification,
            signals=all_signals,
            recommendation=recommendation,
            model_available=model_available,
            score_breakdown=score_breakdown,
        )

    def _heuristic_analysis(
        self, url: str, parsed: Any, features: Dict[str, Any]
    ) -> tuple[List[Signal], int]:
        """Apply URL-based heuristic rules. Returns (signals, score)."""
        signals = []
        score = 0

        if features.get("has_ip_host"):
            signals.append(Signal(
                code="ip_based_host",
                severity="high",
                description="The website uses an IP address instead of a registered domain name. Legitimate sites almost always use domain names.",
                source="heuristic",
            ))
            score += HEURISTIC_WEIGHTS["ip_based_host"]

        if features.get("has_at_symbol"):
            signals.append(Signal(
                code="at_symbol_in_url",
                severity="high",
                description="The URL contains an @ symbol. Browsers interpret everything before @ as credentials, making the visible part appear legitimate while the actual destination differs.",
                source="heuristic",
            ))
            score += HEURISTIC_WEIGHTS["at_symbol_in_url"]

        if features.get("has_double_slash"):
            signals.append(Signal(
                code="double_slash_redirect",
                severity="medium",
                description="The URL path contains a double slash pattern that may indicate an obfuscated redirect to a different site.",
                source="heuristic",
            ))
            score += HEURISTIC_WEIGHTS["double_slash_redirect"]

        subdomain_count = features.get("subdomain_count", 0) or 0
        if subdomain_count > 3:
            signals.append(Signal(
                code="excessive_subdomains",
                severity="medium",
                description=f"The URL has {subdomain_count} subdomain levels. Phishing sites sometimes mimic legitimate domains using excessive subdomains.",
                source="heuristic",
            ))
            score += HEURISTIC_WEIGHTS["excessive_subdomains"]

        if not features.get("is_https"):
            signals.append(Signal(
                code="no_https",
                severity="medium",
                description="The site does not use HTTPS. Any data submitted may be transmitted in plaintext and could be intercepted.",
                source="heuristic",
            ))
            score += HEURISTIC_WEIGHTS["no_https"]

        if features.get("has_suspicious_tld"):
            signals.append(Signal(
                code="suspicious_tld",
                severity="medium",
                description="The domain extension is commonly associated with free, disposable, or low-accountability domain registrations used in phishing campaigns.",
                source="heuristic",
            ))
            score += HEURISTIC_WEIGHTS["suspicious_tld"]

        url_length = features.get("url_length", 0) or 0
        if url_length > 100:
            signals.append(Signal(
                code="long_url",
                severity="low",
                description=f"The URL is unusually long ({url_length} characters). Long URLs can be used to hide the actual destination or overwhelm URL inspection.",
                source="heuristic",
            ))
            score += HEURISTIC_WEIGHTS["long_url"]

        if features.get("has_encoding"):
            signals.append(Signal(
                code="url_encoding",
                severity="low",
                description="The URL contains percent-encoded characters, which can be used to obscure the actual content of the address.",
                source="heuristic",
            ))
            score += HEURISTIC_WEIGHTS["url_encoding"]

        # Compound: IP + credential keywords = stronger signal
        if features.get("has_ip_host") and features.get("has_suspicious_keywords"):
            signals.append(Signal(
                code="ip_with_keywords",
                severity="high",
                description="The URL combines an IP-based host with login or account-related keywords — a pattern strongly associated with credential phishing.",
                source="heuristic",
            ))
            score += HEURISTIC_WEIGHTS["ip_with_keywords"]

        # Compound: Suspicious TLD + credential/brand keywords
        if features.get("has_suspicious_tld") and features.get("has_suspicious_keywords"):
            signals.append(Signal(
                code="tld_with_keywords",
                severity="medium",
                description="The URL combines a high-risk domain extension with credential or account keywords, a pattern frequently observed in phishing impersonation.",
                source="heuristic",
            ))
            score += 15

        return signals, min(score, 100)

    def _dom_analysis(self, dom_features: Dict[str, Any]) -> tuple[List[Signal], int]:
        """Analyze DOM structural features for phishing indicators. Returns (signals, score_bonus)."""
        signals = []
        score = 0

        has_password = dom_features.get("has_password_input", 0)
        has_external_form = dom_features.get("has_external_form", 0)
        external_form_count = dom_features.get("external_form_count", 0) or 0

        if has_password and has_external_form:
            signals.append(Signal(
                code="credential_form_external_submit",
                severity="high",
                description="The page contains a password field whose form submits data to a different domain. This is a hallmark of credential phishing attacks.",
                source="dom",
            ))
            score += 35

        elif has_external_form and external_form_count > 0:
            signals.append(Signal(
                code="form_external_action",
                severity="medium",
                description=f"{external_form_count} form(s) on this page submit data to a different domain than the page itself.",
                source="dom",
            ))
            score += 15

        elif has_password:
            signals.append(Signal(
                code="password_input_detected",
                severity="low",
                description="The page requests your password. Verify the site's identity before entering credentials.",
                source="dom",
            ))
            # Low penalty — many legitimate sites have login forms

        return signals, min(score, 40)

    def _build_recommendation(
        self, classification: str, signals: List[Signal], evidence_level: str = "moderate"
    ) -> str:
        """Build a plain-English recommendation based on classification and evidence adequacy."""
        if classification == "high_risk":
            return (
                "Do not enter passwords, payment information, or any personal data on this site. "
                "Navigate away immediately using your browser's back button. "
                "If you landed here from an email link or search result, the source may have been compromised."
            )
        elif classification == "suspicious":
            return (
                "Exercise caution before interacting with this site. "
                "Verify the site's identity independently (check the exact domain name, look for contact information, "
                "and search for reviews) before entering any sensitive information."
            )
        else:
            if evidence_level == "limited":
                return (
                    "No credential-harvesting indicators detected, but structural evidence is limited. "
                    "Exercise caution if prompted to download files, install software, or grant permissions."
                )
            elif any(s.severity in ("high", "medium") for s in signals):
                return (
                    "No critical threats were detected, but some indicators were noted. "
                    "Review the detected signals and verify the site before sharing sensitive data."
                )
            return (
                "No significant threats detected. The site appears to be low-risk based on available signals. "
                "Always exercise normal caution online."
            )
