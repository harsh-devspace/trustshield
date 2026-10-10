# TrustShield — Adaptive Phishing Detection & Website Trust Engine

> A Chrome Manifest V3 extension + Python FastAPI backend that combines machine learning with real-time heuristic analysis to protect users from phishing attacks.

[![Tests](https://img.shields.io/badge/tests-67%20passed-22c55e)](#testing)
[![Python](https://img.shields.io/badge/python-3.12-3b82f6)](#requirements)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.143-009688)](#backend)
[![Manifest V3](https://img.shields.io/badge/Chrome-Manifest%20V3-ef4444)](#extension)

---

## What It Does

TrustShield analyzes every website you visit using two complementary layers:

| Layer | Where | What |
|-------|-------|------|
| **Local heuristics** | Extension (instant) | URL structure, IP hosts, suspicious TLDs, @ symbols |
| **ML prediction** | FastAPI backend (~43 ms) | RandomForest trained on UCI Phishing Websites Dataset |
| **DOM analysis** | Content script | Form targets, password fields, external iframes |

Results are combined into a 0–100 risk score with classification (`low_risk`, `suspicious`, `high_risk`) and plain-English explanations for every detected signal.

---

## Project Structure

```
trustshield/
├── extension/              # Chrome Manifest V3 extension
│   ├── manifest.json       # Extension configuration (MV3)
│   ├── background.js       # Service worker: scan orchestration, API calls
│   ├── content.js          # Content script: DOM feature extraction
│   ├── popup.html/js/css   # Extension popup UI
│   ├── warning.html/js/css # Full-page warning for high-risk sites
│   └── assets/             # Extension icons (16, 32, 48, 128px)
│
├── backend/
│   ├── app/
│   │   ├── main.py         # FastAPI app with lifespan handler
│   │   ├── schemas.py      # Pydantic request/response models + SSRF protection
│   │   ├── risk_engine.py  # Scoring pipeline (heuristics + ML + DOM)
│   │   ├── model_service.py# Model loading, prediction, metadata
│   │   └── feature_extractor.py  # Server-side URL feature extraction
│   ├── ml/
│   │   ├── train_model.py  # Training pipeline (UCI dataset)
│   │   ├── evaluate_model.py # Evaluation on held-out test set
│   │   └── model_artifacts/
│   │       ├── trustshield_model.joblib   # Trained RandomForest (2.5 MB)
│   │       ├── evaluation_metrics.json    # Real metrics from test set
│   │       └── feature_schema.json        # Feature names and types
│   └── requirements.txt
│
├── tests/
│   ├── test_backend.py         # 48 API and integration tests
│   └── test_feature_extractor.py # 19 unit tests
│
├── docs/                   # Architecture and security documentation
├── scripts/                # Setup and run scripts
├── conftest.py
├── .env.example
└── .gitignore
```

---

## Quick Start

### 1. Prerequisites

- Python 3.12+
- Google Chrome (or Chromium)
- No paid API keys required

### 2. Backend Setup

```bash
# Navigate to project
cd trustshield

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt

# Start the API server
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

The API will be available at `http://localhost:8000`.
- Swagger docs: http://localhost:8000/docs
- Health check: http://localhost:8000/health

### 3. Install the Chrome Extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `trustshield/extension/` directory
5. The TrustShield icon appears in your toolbar

### 4. Run Tests

```bash
pytest tests/ -v
# Expected: 67 passed in ~3 seconds
```

---

## API Reference

### GET /health
```json
{"status": "ok", "model_loaded": true, "version": "1.0.0"}
```

### GET /model-info
Returns ML model metadata, feature list, and evaluation metrics.

### POST /analyze

**Request body:**
```json
{
  "url": "https://example.com",
  "url_features": { "url_length": 23, "is_https": 1 },
  "dom_features": { "has_password_input": 0, "has_external_form": 0 }
}
```

**Response:**
```json
{
  "url_host": "example.com",
  "risk_score": 0,
  "classification": "low_risk",
  "signals": [],
  "recommendation": "No significant threats detected...",
  "model_available": true,
  "api_version": "1.0.0"
}
```

---

## ML Model

| Metric | Value |
|--------|-------|
| Algorithm | RandomForestClassifier (200 estimators) |
| Dataset | UCI Phishing Websites Dataset (CC BY 4.0) |
| Train/Test Split | 80/20 stratified |
| Accuracy | 96.6% |
| AUC-ROC | 99.4% |
| Precision | 95.8% |
| Recall | 96.6% |
| F1 Score | 96.2% |
| False Positive Rate | 3.4% |
| Test Set Size | 2,211 samples |

**Top features by importance:**
1. `has_ip_host` (21.1%)
2. `has_external_form` (20.7%)
3. `has_double_slash` (13.5%)
4. `url_length_encoded` (13.2%)

Retrain: `python backend/ml/train_model.py`

---

## Security & Privacy

**What is NOT transmitted:** browsing history, form values, passwords, cookies, auth tokens, page HTML, user identity.

**What IS transmitted:** Only 17 numeric URL-structure features derived from the current page URL, plus optional DOM structure counts (no content or values).

**SSRF Protection:** The backend explicitly blocks private IP ranges (RFC 1918), loopback, link-local, and cloud metadata endpoints. The backend never fetches user-submitted URLs.

**Extension Permissions:** activeTab, storage, scripting, webNavigation, declarativeNetRequest.

---

## Performance

| Stage | Latency |
|-------|---------|
| Local URL heuristics | < 1 ms |
| DOM feature extraction | 2–5 ms |
| Backend API (warm) | ~43 ms avg |
| Total scan time | 50–80 ms |

---

## Development

```bash
# Retrain the model
python backend/ml/train_model.py

# Evaluate existing model
python backend/ml/evaluate_model.py

# Dev server with auto-reload
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

---

## License

Project code: original work developed for TrustShield.
UCI Phishing Websites Dataset: Creative Commons Attribution 4.0 (CC BY 4.0).
