# TrustShield — Architecture Overview

## System Components

```
┌─────────────────────────────────────────────────────────┐
│                   Chrome Extension (MV3)                 │
│                                                          │
│  background.js (service worker)                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 1. Extract URL features (no network)            │   │
│  │ 2. Get DOM features via scripting API           │   │
│  │ 3. Run local heuristic analysis                 │   │
│  │ 4. Call POST /analyze (optional ML)             │   │
│  │ 5. Blend results → risk score + classification  │   │
│  │ 6. Update badge / trigger warning page          │   │
│  └─────────────────────────────────────────────────┘   │
│                                                          │
│  content.js        popup.js           warning.js        │
│  DOM extraction    UI rendering       Phishing alert     │
└──────────────────────────┬──────────────────────────────┘
                           │  POST /analyze (43 ms avg)
                           ▼
┌─────────────────────────────────────────────────────────┐
│               FastAPI Backend (Python 3.12)              │
│                                                          │
│  main.py → risk_engine.py                               │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 1. Validate URL (Pydantic + SSRF check)         │   │
│  │ 2. Extract server-side URL features             │   │
│  │ 3. Heuristic analysis (9 rules, weighted)       │   │
│  │ 4. DOM signal analysis (form/iframe patterns)   │   │
│  │ 5. ML prediction (RandomForest, 11 features)    │   │
│  │ 6. Weighted blend → final score + signals       │   │
│  └─────────────────────────────────────────────────┘   │
│                                                          │
│  model_service.py                                       │
│  └── trustshield_model.joblib (RandomForest, 200 trees) │
└─────────────────────────────────────────────────────────┘
```

## Scoring Algorithm

### Heuristic Rules (max 100 points, no network)

| Rule | Points | Severity |
|------|--------|----------|
| IP address as hostname | 35 | High |
| @ symbol in URL | 28 | High |
| IP + credential keywords | 22 | High |
| Suspicious TLD (.tk, .ml, etc.) | 20 | Medium |
| >3 subdomain levels | 18 | Medium |
| No HTTPS | 14 | Medium |
| Double slash redirect pattern | 15 | Medium |
| URL length > 100 chars | 8 | Low |
| Percent-encoded characters | 5 | Low |

### DOM Signals (max 40 bonus points)

| Signal | Bonus |
|--------|-------|
| Password field + external form action | +35 (High) |
| External form action only | +15 (Medium) |

### ML Contribution (up to 60 points)

- ML provides phishing probability (0.0–1.0)
- Contribution = `round(probability × 60)`
- High-confidence heuristics override ML blending

### Final Blending

```
If model available AND no strong heuristics:
    score = 0.4 × heuristic_score + 0.6 × ml_contribution

If model available AND strong heuristics present:
    score = max(heuristic_led, ml_led)

If model unavailable:
    score = heuristic_score + dom_bonus
```

### Classification Thresholds

| Score | Classification |
|-------|---------------|
| 0–39 | low_risk |
| 40–69 | suspicious |
| 70–100 | high_risk |

## Data Flow

```
User navigates to URL
       │
       ▼
background.js:
  - Extract 17 URL features (instant, local)
  - Inject content script → get 8 DOM features
  - Run local heuristics → local score
  - POST /analyze with features
       │
       ▼
FastAPI /analyze:
  - Validate + SSRF check (Pydantic)
  - Server-side feature extraction
  - Heuristic scoring
  - ML.predict_proba() → phishing probability
  - Blend scores
  - Return AnalyzeResponse (JSON)
       │
       ▼
background.js:
  - Blend API result with local result
  - Cache result (5 min TTL)
  - Update extension badge
  - Store result for popup
       │
       ├── risk_score >= 70 → trigger warning page
       │
       └── popup.js → render results UI
```

## Privacy by Design

All data minimization happens at the feature extraction layer:

1. The content script reads only structure (element counts, form `action` attributes)
2. Form values, input content, cookies, localStorage are never accessed
3. Background.js sends only the 17 numeric URL features + 8 numeric DOM features
4. The backend receives no user identity, no browsing history
5. SSRF protection ensures the backend never fetches user-submitted URLs
6. Scan results are cached locally in the extension (not sent anywhere)
