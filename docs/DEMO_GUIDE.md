# TrustShield — Local Demo Guide

This guide walks through demonstrating TrustShield end-to-end on a local machine.

## Prerequisites

- Backend running: `uvicorn backend.app.main:app --host 127.0.0.1 --port 8000`
- Extension loaded in Chrome (Developer mode, unpacked from `extension/`)

---

## Demo Script (5 minutes)

### Step 1: Show the backend is running (30 sec)

Open a browser and visit `http://localhost:8000/docs`

**Show:** The interactive Swagger UI with three endpoints.

**Key talking points:**
- The API is fully local — no cloud dependency
- The ML model loads from disk at startup (2.5 MB RandomForest)

---

### Step 2: Demonstrate a safe site (60 sec)

1. Click the TrustShield icon in Chrome
2. Navigate to `https://www.github.com`
3. Click **"Scan This Site"** in the popup

**Expected result:**
- Risk score: 0–15
- Classification: **Low Risk** (green)
- No critical signals
- Scan time: ~50-80ms

**Key talking point:** Well-known HTTPS sites score low. The ML model and heuristics agree.

---

### Step 3: Demonstrate a suspicious URL (90 sec)

In the browser, navigate to this URL (it's a test URL that's not a real phishing site — it's used for demonstration):

```
http://phishing-test.tk/login?verify=account
```

Or use the API directly:
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://phishing-test.tk/login?verify=account"}'
```

**Expected signals:**
- `no_https` [medium] — HTTP connection
- `suspicious_tld` [medium] — .tk domain
- `has_suspicious_keywords` — "login", "verify", "account"

**Key talking point:** Multiple signals combine for a higher score than any single indicator alone.

---

### Step 4: Demonstrate high-risk detection (90 sec)

Use the API:
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://203.0.113.5@legitimate-bank.com@evil.tk/secure/login"}'
```

**Expected result:**
- Risk score: 70+
- Classification: **High Risk** (red)
- Signals: `at_symbol_in_url` [high], `suspicious_tld` [medium], `no_https` [medium], `ml_phishing_prediction` [high]

**Key talking point:** The @ symbol trick makes browsers display the rightmost part as the hostname, hiding the actual IP-based destination.

---

### Step 5: Privacy demonstration (60 sec)

Open Chrome DevTools (F12) → Network tab while scanning a site.

**Show:** The only outbound request is `POST /analyze` containing only numeric feature values — no HTML, no cookies, no form data.

**Key talking point:** "We extract 17 numbers from the URL structure and 8 counts from the DOM. That's all we send."

---

## API Demo Commands

### Health check
```bash
curl http://localhost:8000/health
```

### Model information
```bash
curl http://localhost:8000/model-info
```

### Analyze a benign URL
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'
```

### Analyze with DOM features (simulating extension)
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://192.0.2.100/secure/login",
    "dom_features": {
      "has_password_input": 1,
      "has_external_form": 1,
      "external_form_count": 1,
      "form_count": 1
    }
  }'
```

**Expected:** High risk score (IP host + password + external form = credential phishing pattern)

---

## Running the Test Suite

```bash
# Activate venv first
venv\Scripts\activate  # Windows

# Run all tests
pytest tests/ -v

# Expected output:
# 67 passed in ~3 seconds
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Extension not loading | Check Developer mode is ON in chrome://extensions |
| API not responding | Start uvicorn: `scripts\start.ps1` |
| Tests failing | Activate venv: `venv\Scripts\activate` |
| Model not loading | File exists: `backend/ml/model_artifacts/trustshield_model.joblib` |
