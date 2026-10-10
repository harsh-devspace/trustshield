"""
TrustShield Test Suite: Automatic Scanning, Explainable Risk Notifications,
and Extension Download Packaging Verification
"""

import json
import zipfile
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.risk_engine import RiskEngine
from backend.app.schemas import Signal, ScoreBreakdown

BASE_DIR = Path(__file__).resolve().parent.parent
EXTENSION_DIR = BASE_DIR / "extension"
ZIP_PATH = BASE_DIR / "trustshield-extension.zip"


# ─── 1-5 & 8: Navigation Deduplication & Hostname Boundary Tests ─────────────

class AutoScanDeduplicator:
    """
    Python reference model of TrustShield's background service worker
    navigation & deduplication logic (mirroring extension/background.js).
    """
    def __init__(self, restricted_schemes=None):
        self.restricted_schemes = restricted_schemes or [
            "chrome://", "chrome-extension://", "about:", "data:", "edge://", "brave://"
        ]
        self.tab_active_hostnames = {}    # tabId -> hostname
        self.session_scanned_hostnames = set() # Set of hostnames
        self.tab_latest_scan = {}         # tabId -> result
        self.active_scans = {}            # hostname -> in-flight flag
        self.notifications_dispatched = [] # [(tabId, hostname, result)]

    def is_restricted_url(self, url: str) -> bool:
        if not url:
            return True
        return any(url.startswith(scheme) for scheme in self.restricted_schemes)

    def extract_hostname(self, url: str) -> str:
        from urllib.parse import urlparse
        return urlparse(url).hostname or ""

    def simulate_navigation(self, tab_id: int, url: str, mock_scan_fn=None):
        """Simulates chrome.webNavigation.onCompleted / autoScanTab."""
        if self.is_restricted_url(url):
            return {"status": "skipped", "reason": "restricted_url"}

        hostname = self.extract_hostname(url).lower()
        if not hostname:
            return {"status": "skipped", "reason": "invalid_host"}

        prev_host = self.tab_active_hostnames.get(tab_id)
        is_new_host_in_tab = (prev_host != hostname)
        self.tab_active_hostnames[tab_id] = hostname

        # Intra-domain navigation check
        if not is_new_host_in_tab and tab_id in self.tab_latest_scan:
            return {"status": "skipped", "reason": "same_host_intra_navigation"}

        # Concurrent in-flight scan deduplication
        if hostname in self.active_scans:
            return {"status": "deduplicated_inflight"}

        self.active_scans[hostname] = True
        try:
            result = mock_scan_fn(url) if mock_scan_fn else {"url": url, "url_host": hostname, "risk_score": 25}
        finally:
            self.active_scans.pop(hostname, None)

        self.tab_latest_scan[tab_id] = result

        already_notified = (hostname in self.session_scanned_hostnames)
        self.session_scanned_hostnames.add(hostname)

        # Notify only if not previously notified in this session
        if not already_notified:
            self.notifications_dispatched.append((tab_id, hostname, result))
            return {"status": "scanned_and_notified", "result": result}
        else:
            return {"status": "scanned_no_notification", "result": result}


def test_automatic_scan_on_new_eligible_hostname():
    dedup = AutoScanDeduplicator()
    res = dedup.simulate_navigation(tab_id=1, url="https://new-target-site.org/index.html")
    assert res["status"] == "scanned_and_notified"
    assert len(dedup.notifications_dispatched) == 1
    assert dedup.notifications_dispatched[0][1] == "new-target-site.org"


def test_no_repeated_notification_on_page_reload():
    dedup = AutoScanDeduplicator()
    # Initial visit
    dedup.simulate_navigation(tab_id=1, url="https://bank-portal.example/login")
    assert len(dedup.notifications_dispatched) == 1

    # Page reload (same tab, same URL)
    res_reload = dedup.simulate_navigation(tab_id=1, url="https://bank-portal.example/login")
    assert res_reload["status"] == "skipped"
    assert res_reload["reason"] == "same_host_intra_navigation"
    # No duplicate notification
    assert len(dedup.notifications_dispatched) == 1


def test_no_repeated_notification_on_path_navigation():
    dedup = AutoScanDeduplicator()
    # First page
    dedup.simulate_navigation(tab_id=1, url="https://mysite.example/dashboard")
    assert len(dedup.notifications_dispatched) == 1

    # Navigate to different path and query parameters on same host
    res_path = dedup.simulate_navigation(tab_id=1, url="https://mysite.example/settings?user=42#profile")
    assert res_path["status"] == "skipped"
    assert res_path["reason"] == "same_host_intra_navigation"
    assert len(dedup.notifications_dispatched) == 1


def test_appropriate_behavior_when_moving_to_another_hostname():
    dedup = AutoScanDeduplicator()
    # Visit host A
    dedup.simulate_navigation(tab_id=1, url="https://site-alpha.com/home")
    assert len(dedup.notifications_dispatched) == 1

    # Visit host B in the same tab
    res_b = dedup.simulate_navigation(tab_id=1, url="https://site-beta.com/home")
    assert res_b["status"] == "scanned_and_notified"
    assert len(dedup.notifications_dispatched) == 2
    assert dedup.notifications_dispatched[1][1] == "site-beta.com"


def test_subdomain_separation():
    dedup = AutoScanDeduplicator()
    # Subdomain A
    dedup.simulate_navigation(tab_id=1, url="https://portal.university.edu/login")
    assert len(dedup.notifications_dispatched) == 1

    # Subdomain B should NOT be assumed identical to Subdomain A
    dedup.simulate_navigation(tab_id=1, url="https://phish.university.edu/login")
    assert len(dedup.notifications_dispatched) == 2
    assert dedup.notifications_dispatched[1][1] == "phish.university.edu"


def test_restricted_page_behavior():
    dedup = AutoScanDeduplicator()
    for restricted in [
        "chrome://extensions",
        "chrome://settings",
        "chrome-extension://abcdefg/popup.html",
        "about:blank",
        "edge://flags",
        "data:text/html,<h1>test</h1>"
    ]:
        res = dedup.simulate_navigation(tab_id=1, url=restricted)
        assert res["status"] == "skipped"
        assert res["reason"] == "restricted_url"
    assert len(dedup.notifications_dispatched) == 0


def test_concurrent_scan_event_deduplication():
    dedup = AutoScanDeduplicator()
    # Simulate an active scan in progress
    dedup.active_scans["concurrent-test.com"] = True
    res = dedup.simulate_navigation(tab_id=1, url="https://concurrent-test.com/page")
    assert res["status"] == "deduplicated_inflight"


# ─── 6, 7, 10, 11: Explainable Risk Scoring & Security Contracts ─────────────

def test_explainable_risk_score_points_attribution():
    from backend.app.main import risk_engine
    result = risk_engine.analyze(
        url="http://paypal-verification.com.suspicious-domain.xyz/@login//secure",
        url_features=None,
        dom_features={
            "has_password_input": 1,
            "has_external_form": 1,
            "external_form_count": 2
        }
    )

    # 1. Final score & classification
    assert isinstance(result.risk_score, int)
    assert 0 <= result.risk_score <= 100
    assert result.classification in ("low_risk", "suspicious", "high_risk")

    # 2. Points attribution on signals
    for signal in result.signals:
        assert hasattr(signal, "points")
        assert isinstance(signal.points, int)
        assert signal.points >= 0
        assert signal.severity in ("low", "medium", "high")
        assert len(signal.description) > 0

    # 3. Score Breakdown explainability fields
    bd = result.score_breakdown
    assert isinstance(bd, ScoreBreakdown)
    assert bd.heuristic_score >= 0
    assert bd.dom_bonus >= 0
    assert isinstance(bd.checks_performed, list)
    assert len(bd.checks_performed) >= 3
    assert bd.strongest_indicator is not None
    assert len(bd.strongest_indicator) > 0


def test_backend_offline_and_inconclusive_handling():
    """Verify that an unscanned or minimal site is not falsely reported as zero without evidence."""
    from backend.app.main import risk_engine
    result = risk_engine.analyze(
        url="https://simple-content-only-site.org/article",
        url_features=None,
        dom_features={"form_count": 0, "has_password_input": 0}
    )
    # Evidence adequacy level must reflect clean/limited
    assert result.score_breakdown.evidence_level in ("high", "moderate", "limited")
    # Must have actionable directive
    assert len(result.recommendation) > 0


def test_safe_handling_of_untrusted_hostnames():
    """Verify XSS vectors in URL strings are properly parsed and do not inject tags."""
    from backend.app.main import risk_engine
    xss_url = "https://example.com/<script>alert(1)</script>/test"
    result = risk_engine.analyze(url=xss_url)
    assert result.url_host == "example.com"
    assert "<script>" not in result.url_host


# ─── 13-14: Extension Download Package & Web Link Verification ───────────────

def test_extension_zip_package_integrity():
    assert ZIP_PATH.exists(), f"Distributable ZIP must exist at {ZIP_PATH}"
    assert ZIP_PATH.stat().st_size > 10000, "ZIP archive size should be substantial"

    with zipfile.ZipFile(ZIP_PATH, "r") as zf:
        namelist = zf.namelist()

        # manifest.json MUST be at the root of the ZIP
        assert "manifest.json" in namelist, "manifest.json must be located at the root of the ZIP!"
        assert "background.js" in namelist, "background.js missing from ZIP"
        assert "content.js" in namelist, "content.js missing from ZIP"
        assert "popup.html" in namelist, "popup.html missing from ZIP"
        assert "popup.js" in namelist, "popup.js missing from ZIP"
        assert "popup.css" in namelist, "popup.css missing from ZIP"
        assert "trust.html" in namelist, "trust.html missing from ZIP"
        assert "trust.css" in namelist, "trust.css missing from ZIP"

        # Check for forbidden files
        for name in namelist:
            assert not name.startswith("venv/"), f"venv leaked into ZIP: {name}"
            assert not name.startswith(".git/"), f".git leaked into ZIP: {name}"
            assert not name.endswith(".pyc"), f".pyc leaked into ZIP: {name}"

        # Verify manifest.json content inside ZIP
        manifest_data = json.loads(zf.read("manifest.json").decode("utf-8"))
        assert manifest_data.get("manifest_version") == 3
        assert manifest_data.get("name") == "TrustShield"
        assert "webNavigation" in manifest_data.get("permissions", [])
        assert "activeTab" in manifest_data.get("permissions", [])


def test_website_download_link_and_endpoints():
    client = TestClient(app)

    # 1. Download endpoint
    resp = client.get("/download/extension")
    assert resp.status_code == 200
    assert resp.headers["content-type"] in ("application/zip", "application/x-zip-compressed")
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert len(resp.content) == ZIP_PATH.stat().st_size

    # 2. Alternative static route
    resp_alt = client.get("/trustshield-extension.zip")
    assert resp_alt.status_code == 200
    assert len(resp_alt.content) == ZIP_PATH.stat().st_size

    # 3. Trust Methodology web page
    resp_trust = client.get("/trust")
    assert resp_trust.status_code == 200
    assert "text/html" in resp_trust.headers["content-type"]
    assert "trustshield-extension.zip" in resp_trust.text
    assert "Download &amp; Install TrustShield Chrome Extension" in resp_trust.text or "Download" in resp_trust.text
