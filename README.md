# TrustShield — Adaptive Phishing Detection & Website Trust Engine

> An enterprise-grade, privacy-first cybersecurity platform combining a Chrome Manifest V3 extension, an explainable machine-learning inference pipeline, and a FastAPI backend to detect zero-day phishing, typosquatting, IDN homoglyphs, and credential-harvesting attacks in real time.

[![Tests](https://img.shields.io/badge/tests-115%20passed-22c55e?style=flat-square)](#testing)
[![Python](https://img.shields.io/badge/python-3.12-3b82f6?style=flat-square)](#requirements)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.143-009688?style=flat-square)](#backend)
[![Manifest V3](https://img.shields.io/badge/Chrome-Manifest%20V3-ef4444?style=flat-square)](#extension)
[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fharsh-devspace%2Ftrustshield)
[![License](https://img.shields.io/badge/license-MIT-purple?style=flat-square)](#license)

---

## 🛡️ Key Capabilities

- **Automatic Non-Blocking Scanning**: Chrome MV3 service worker monitors top-level navigation, extracts structural attributes, and evaluates risk without delaying page rendering.
- **Intelligent Session Deduplication**: Evaluates each unique hostname once per session; suppresses redundant notifications on intra-domain path navigation and page reloads.
- **Shadow DOM Risk Notification**: Injected 5-second HUD banner with Cyber Forensics Workbench styling, hover-pause countdown, and safe DOM text rendering.
- **Transparent Mathematical Attribution**: Full point contribution breakdown for each detected heuristic, DOM anomaly, and ML inference output (`points` per signal, `strongest_indicator`).
- **Zero-Trust Privacy Architecture**: **Zero** credential or form-value capture. Benign browsing history is never logged, stored, or transmitted.
- **Offline Resilience**: Complete deterministic heuristic fallback and local cached models if the remote backend or internet connection is offline.

---

## 🏛️ System Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        CHROME BROWSER SANDBOX                          │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  webNavigation.onCompleted  ──►  Background Service Worker (MV3)       │
│  (Top-level navigation)          ├── Hostname-Level Deduplication      │
│                                  ├── Local Lexical Heuristic Engine    │
│                                  └── Active Scan Promise Merging       │
│                                              │                         │
│  Content Script (Isolated)                   ▼                         │
│  ├── Structural DOM Auditing      REST API POST /analyze               │
│  │   (External forms, inputs)     (Derived features only, no HTML)     │
│  └── Shadow DOM 5s Notification              │                         │
│      (Hover pause, Auto-dismiss)             │                         │
└──────────────────────────────────────────────┼─────────────────────────┘
                                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        TRUSTSHIELD FASTAPI BACKEND                     │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  Tier 1: High-Confidence Heuristics (IP Host, @ Lure, Shannon Entropy) │
│  Tier 2: DOM Form Action Audit (External Password/Card Submit Bonus)   │
│  Tier 3: Random Forest Classifier (UCI Phishing Schema, 11 features)   │
│  Tier 4: Optional Threat Intelligence (Google Safe Browsing v4)        │
│                                                                        │
│  Output: Composite 0–100 Score + Explainable Signal Points Attribution │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📂 Repository Structure

```
trustshield/
├── extension/                  # Chrome Manifest V3 Extension
│   ├── manifest.json           # MV3 configuration & permissions
│   ├── background.js           # Service worker: auto-scan & deduplication
│   ├── content.js              # Content script: structural DOM & Shadow DOM HUD
│   ├── popup.html/js/css       # Forensics Workbench popup UI
│   ├── trust.html/css          # Detection & Trust Methodology website
│   ├── warning.html/js/css     # High-risk interception screen
│   ├── trustshield-extension.zip # Packaged distributable archive
│   └── assets/                 # High-resolution branding icons
│
├── backend/
│   ├── app/
│   │   ├── main.py             # FastAPI entrypoint, CORS, routes & lifespan
│   │   ├── schemas.py          # Pydantic models, signal points & SSRF filters
│   │   ├── risk_engine.py      # Multi-tier risk engine & explainability
│   │   ├── model_service.py    # Random Forest loader & inference
│   │   ├── threat_intel.py     # Optional threat feed integrations
│   │   └── feature_extractor.py# Server-side URL feature extraction
│   ├── ml/
│   │   ├── train_model.py      # Stratified training pipeline
│   │   ├── evaluate_model.py   # Benchmark evaluation script
│   │   └── model_artifacts/
│   │       ├── trustshield_model.joblib # Serialized model (2.5 MB)
│   │       ├── evaluation_metrics.json  # Held-out benchmark metrics
│   │       └── feature_schema.json      # UCI-aligned feature definition
│   └── requirements.txt        # Full development & training dependencies
│
├── api/
│   └── index.py                # Serverless entrypoint for Vercel
├── test-bench/                 # Local offline test scenarios (Safe fixtures)
├── tests/                      # Automated test suite (115 passing tests)
├── scripts/
│   └── package_extension.py    # Automated extension packaging script
├── trustshield-extension.zip   # Distributable root ZIP package
├── index.html & trust.css      # Web deployment landing page
├── vercel.json                 # Vercel deployment routing & rewrites
├── requirements.txt            # Lean runtime requirements for Vercel
└── .env.example                # Sample configuration template
```

---

## 🚀 Quick Start & Installation

### 1. Install the Chrome Extension ("Load Unpacked")

1. Download **`trustshield-extension.zip`** from the website or repository root.
2. Extract the ZIP file to a local directory on your computer.
3. Open Google Chrome and navigate to `chrome://extensions`.
4. Enable **Developer mode** using the toggle switch in the upper-right corner.
5. Click **Load unpacked** in the top-left toolbar.
6. Select the extracted `extension/` directory (containing `manifest.json`).
7. Pin the TrustShield shield icon to your toolbar.

### 2. Local Backend Setup

```bash
# Clone the repository
git clone https://github.com/harsh-devspace/trustshield.git
cd trustshield

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate  # macOS / Linux

# Install dependencies
pip install -r backend/requirements.txt

# Start the development server
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

- **Interactive API Documentation**: `http://localhost:8000/docs`
- **Methodology & Download Site**: `http://localhost:8000/trust`
- **Health Check**: `http://localhost:8000/health`

---

## 🧪 Automated Testing

TrustShield includes an extensive test suite verifying detection accuracy, heuristic edge cases, SSRF protection, navigation deduplication, and ZIP packaging integrity.

```bash
pytest tests/ -v
```

**Results:**
- **115 tests passed** with 100% success rate.
- **Average scan latency:** **39.42 ms** (measured across 10 benchmark runs; budget: < 200 ms).

---

## 🌐 Web & Cloud Deployment

### Deploying to Vercel

TrustShield is pre-configured for one-click deployment on [Vercel](https://vercel.com):

1. **Connect Repository**: Import `harsh-devspace/trustshield` into Vercel.
2. **Framework Preset**: Select **Other**.
3. **Build & Output Settings**: Leave defaults (Root Directory: `./`).
4. **Environment Variables**: None required for standard operation (optional `GOOGLE_SAFE_BROWSING_API_KEY`).
5. **Deploy**: Vercel automatically deploys:
   - Static TrustShield methodology website and download portal.
   - Serverless Python FastAPI backend at `/analyze` and `/health`.

---

## 🔒 Privacy & Threat Model

| Principle | Technical Implementation |
| :--- | :--- |
| **Zero Credential Capture** | Content script counts element frequencies only (`forms.length`, `passwordInputs.length`). Never inspects `input.value` or text nodes. |
| **No Browsing History Stored** | URLs are analyzed in-flight; no database logs user browsing activity. |
| **SSRF Defense-in-Depth** | Backend blocks RFC 1918, RFC 5737, loopback (`127.0.0.0/8`), link-local, and cloud metadata (`169.254.169.254`). |
| **UI Isolation** | Injected notifications use Shadow DOM (`attachShadow`) to prevent CSS and script collision with host pages. |

---

## 📄 License

TrustShield is open-source software licensed under the [MIT License](LICENSE).  
The machine learning model was trained using features derived from the UCI Phishing Websites Dataset (CC BY 4.0).
