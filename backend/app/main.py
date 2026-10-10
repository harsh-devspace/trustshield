"""
TrustShield Backend — FastAPI Application Entry Point

Endpoints:
  GET  /health        — Liveness check
  POST /analyze       — URL risk analysis with ML + heuristics
  GET  /model-info    — Model metadata and feature schema
"""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import time
import logging

from .schemas import AnalyzeRequest, AnalyzeResponse, HealthResponse, ModelInfoResponse
from .risk_engine import RiskEngine
from .model_service import ModelService
from .threat_intel import ThreatIntelService

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("trustshield")

# ─── Service instances ────────────────────────────────────────────────────────
# Instantiated before the app so they are accessible to routes and tests alike.
model_service = ModelService()
threat_intel_service = ThreatIntelService()
risk_engine = RiskEngine(model_service=model_service, threat_intel=threat_intel_service)


# ─── Lifespan ────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler (replaces deprecated @app.on_event)."""
    # --- startup ---
    logger.info("TrustShield API starting…")
    loaded = model_service.load_model()
    if loaded:
        logger.info("ML model loaded successfully.")
    else:
        logger.warning("ML model not available — falling back to heuristics only.")

    yield  # application runs here

    # --- shutdown (nothing to clean up currently) ---
    logger.info("TrustShield API shutting down.")


# ─── App setup ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="TrustShield API",
    description="Adaptive phishing detection and website trust engine — powered by ML and heuristic analysis.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS — allow the extension and local dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Extension origin cannot be predicted; restrict in production
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    max_age=300,
)

# ─── Error handlers ───────────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Please try again."},
    )

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    tags=["Infrastructure"],
)
async def health():
    """Returns API health status and model availability."""
    return HealthResponse(
        status="ok",
        model_loaded=model_service.is_loaded(),
        version="1.0.0",
    )


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Analyze a URL for phishing risk",
    tags=["Analysis"],
)
async def analyze(request: AnalyzeRequest):
    """
    Analyzes a URL and optional pre-extracted DOM features for phishing risk.

    Returns a structured risk assessment including:
    - Numerical risk score (0–100)
    - Classification (low_risk | suspicious | high_risk)
    - Detected signals with explanations
    - Recommendation
    - Model availability status

    Note: The backend never fetches the submitted URL.
    All analysis is based on the URL string and pre-extracted features only.
    """
    t_start = time.perf_counter()

    try:
        result = risk_engine.analyze(
            url=str(request.url),
            url_features=request.url_features,
            dom_features=request.dom_features,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Analysis error for {request.url}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Analysis failed.")

    elapsed_ms = round((time.perf_counter() - t_start) * 1000, 2)
    logger.info(
        f"analyze | host={result.url_host} score={result.risk_score} "
        f"class={result.classification} elapsed={elapsed_ms}ms"
    )

    return result


@app.get(
    "/model-info",
    response_model=ModelInfoResponse,
    summary="Get ML model metadata",
    tags=["Analysis"],
)
async def model_info():
    """Returns metadata about the loaded ML model, including features and evaluation metrics."""
    info = model_service.get_model_info()
    return ModelInfoResponse(**info)


@app.get(
    "/threat-intel/status",
    summary="Threat intelligence configuration status",
    tags=["Infrastructure"],
)
async def threat_intel_status():
    """Returns the operational status of external threat intelligence feeds."""
    return {
        "configured": threat_intel_service.is_configured(),
        "provider": "google_safe_browsing" if threat_intel_service.is_configured() else "none",
        "mode": "hybrid_threat_intel_and_local" if threat_intel_service.is_configured() else "fully_local_ml_heuristics",
        "notice": (
            "Missing threat feed match != Safe. Zero-day phishing domains are not yet indexed in feeds. "
            "TrustShield uses multi-layer local ML and heuristic analysis regardless of threat feed status."
        ),
    }


@app.get(
    "/methodology",
    summary="Transparent detection methodology overview",
    tags=["Transparency"],
)
async def methodology():
    """Returns transparent overview of detection architecture, features, and evidence levels."""
    return {
        "engine": "TrustShield Adaptive Phishing Detection & Website Trust Engine",
        "architecture": {
            "tier_1_heuristics": "High-confidence structural URL pattern rules (IP host, @ symbol, double slash, suspicious TLD)",
            "tier_2_dom_signals": "Privacy-preserving structural DOM checks (external form actions, credential input counts; no field values collected)",
            "tier_3_ml_inference": "Random Forest classifier trained on 11 structural features mapping to UCI Phishing dataset schema",
            "tier_4_threat_intel": "Optional Google Safe Browsing Lookup v4 integration",
        },
        "score_interpretation": {
            "0-39": "Low Risk (absence of detected structural credential-theft patterns)",
            "40-69": "Suspicious (concerning structural attributes or medium model probability)",
            "70-100": "High Risk (credential theft indicators, external submit targets, or confirmed threat feed match)",
        },
        "privacy_guarantee": "Zero collection of user passwords, form inputs, cookies, tokens, or browsing history.",
    }


# ─── Extension Distribution & Website Endpoints ──────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent.parent
APP_DIR = Path(__file__).resolve().parent
EXTENSION_DIR = BASE_DIR / "extension"
ZIP_PATH = BASE_DIR / "trustshield-extension.zip"

INDEX_HTML_CANDIDATES = [
    BASE_DIR / "index.html",
    APP_DIR / "index.html",
    Path("index.html"),
    EXTENSION_DIR / "trust.html",
    APP_DIR / "trust.html",
    Path("extension/trust.html"),
]

TRUST_CSS_CANDIDATES = [
    BASE_DIR / "trust.css",
    APP_DIR / "trust.css",
    Path("trust.css"),
    EXTENSION_DIR / "trust.css",
    Path("extension/trust.css"),
]


def _resolve_file(candidates: list[Path]) -> Path | None:
    for c in candidates:
        if c.exists() and c.is_file():
            return c
    return None


@app.get(
    "/",
    response_class=HTMLResponse,
    summary="TrustShield Portal & Methodology",
    tags=["Frontend"],
    include_in_schema=False,
)
@app.get(
    "/index.html",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def root_index():
    """Serves the TrustShield trust, transparency, and installation guide webpage."""
    f = _resolve_file(INDEX_HTML_CANDIDATES)
    if f:
        return HTMLResponse(content=f.read_text(encoding="utf-8"))
    raise HTTPException(status_code=404, detail="index.html not found.")


@app.get(
    "/trust.css",
    include_in_schema=False,
)
async def trust_css():
    """Serves the stylesheet for the TrustShield transparency webpage."""
    f = _resolve_file(TRUST_CSS_CANDIDATES)
    if f:
        return FileResponse(path=f, media_type="text/css")
    raise HTTPException(status_code=404, detail="trust.css not found.")


@app.get(
    "/trust",
    response_class=HTMLResponse,
    summary="Interactive TrustShield Detection & Trust Methodology Website",
    tags=["Transparency"],
)
async def trust_page():
    """Serves the TrustShield trust, transparency, and installation guide webpage."""
    return await root_index()


@app.get(
    "/download/extension",
    summary="Download TrustShield Chrome Extension (.ZIP)",
    tags=["Distribution"],
)
@app.get(
    "/trustshield-extension.zip",
    summary="Download TrustShield Chrome Extension (.ZIP)",
    tags=["Distribution"],
)
async def download_extension():
    """Serves the complete distributable TrustShield Chrome Manifest V3 extension package."""
    zip_candidates = [
        ZIP_PATH,
        Path("trustshield-extension.zip"),
        APP_DIR / "trustshield-extension.zip",
        EXTENSION_DIR / "trustshield-extension.zip",
        Path("extension/trustshield-extension.zip"),
    ]
    f = _resolve_file(zip_candidates)
    if f:
        return FileResponse(
            path=f,
            filename="trustshield-extension.zip",
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=trustshield-extension.zip"},
        )
    raise HTTPException(
        status_code=404,
        detail="Extension ZIP package not found. Run scripts/package_extension.py first.",
    )


# Mount static assets if directories exist
for asset_dir in [
    BASE_DIR / "extension" / "assets",
    EXTENSION_DIR / "assets",
    APP_DIR / "assets",
    Path("extension/assets"),
]:
    if asset_dir.exists() and asset_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(asset_dir)), name="assets")
        app.mount("/extension/assets", StaticFiles(directory=str(asset_dir)), name="extension_assets")
        break


