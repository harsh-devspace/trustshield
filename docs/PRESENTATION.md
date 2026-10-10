# TrustShield — Presentation Outline (8 Slides)

---

## Slide 1: Title

**TrustShield**
Adaptive Phishing Detection & Website Trust Engine

- Chrome Extension + ML Backend
- Real-time analysis, no browsing history transmitted
- 96.6% accuracy on UCI Phishing Dataset

---

## Slide 2: The Problem

**Phishing attacks are the #1 cybersecurity threat to end users.**

- 3.4 billion phishing emails sent daily (Statista 2024)
- 36% of data breaches involve phishing (Verizon DBIR)
- Existing browser warnings rely on known-bad URL lists
- New phishing sites are live for < 24 hours — lists can't keep up

**The gap:** URL-list approaches miss novel, freshly-registered phishing domains.

---

## Slide 3: Our Approach

**Three-layer defense, running in parallel:**

```
Layer 1: URL Heuristics        (instant, 0ms, no network)
Layer 2: DOM Structure Signals (2-5ms, page inspection)
Layer 3: ML Prediction         (43ms, RandomForest backend)
          ↓
    Combined risk score (0-100)
    Explainable signals
    Plain-English recommendation
```

Key insight: No single layer is sufficient. Combining all three reduces both false positives and false negatives.

---

## Slide 4: Technical Architecture

[Architecture diagram from docs/ARCHITECTURE.md]

- Chrome Manifest V3 Service Worker
- FastAPI (Python) backend with lifespan handler
- scikit-learn RandomForestClassifier (200 trees, 11 features)
- Trained on UCI Phishing Websites Dataset (CC BY 4.0)
- No external API dependencies required

---

## Slide 5: ML Model Details

**Dataset:** UCI Phishing Websites Dataset
- 11,055 samples (phishing + legitimate)
- 80/20 stratified train/test split

**Results on held-out test set (n=2,211):**

| Metric | Score |
|--------|-------|
| Accuracy | 96.6% |
| AUC-ROC | 99.4% |
| Precision | 95.8% |
| Recall | 96.6% |
| False Positive Rate | 3.4% |

**Top signal:** IP address as hostname (21.1% feature importance)

---

## Slide 6: Privacy & Security

**"Protection without surveillance"**

What is NEVER transmitted:
- ❌ Browsing history
- ❌ Passwords or form values
- ❌ Cookies or tokens
- ❌ Page HTML content

What IS sent (per scan):
- ✅ 17 numeric URL structure features
- ✅ 8 numeric DOM counts (no content)

Additional protections:
- SSRF protection blocks private IP ranges
- Content Security Policy prevents code injection
- Least-privilege extension permissions

---

## Slide 7: Live Demo

**Demo flow:**
1. Load extension from `extension/` folder
2. Start backend: `uvicorn backend.app.main:app`
3. Visit `https://www.google.com` → Score: 0 (Low Risk)
4. Visit `http://phishing-test.tk/login` → Score: 55+ (Suspicious)
5. API call with IP+@ phishing URL → Score: 70+ (High Risk)
6. Show DevTools Network tab → only numeric features transmitted

**Performance:** ~50-80ms total scan time

---

## Slide 8: Roadmap & Conclusion

**What works today:**
- ✅ 67/67 automated tests passing
- ✅ Live backend with ML prediction
- ✅ Chrome extension with popup and warning page
- ✅ End-to-end integration
- ✅ 43ms average backend latency

**Future enhancements:**
- SafeBrowsing / PhishTank API integration (API keys required)
- IDN homograph detection
- Firefox support (WebExtension MV3)
- Warning page: "Proceed anyway" telemetry opt-in
- Dashboard for IT administrators

**TrustShield — Protecting users without watching them.**
