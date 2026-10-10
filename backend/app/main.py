"""
TrustShield Backend — FastAPI Application Entry Point

Endpoints:
  GET  /health        — Liveness check
  POST /analyze       — URL risk analysis with ML + heuristics
  GET  /model-info    — Model metadata and feature schema
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time
import logging

from .schemas import AnalyzeRequest, AnalyzeResponse, HealthResponse, ModelInfoResponse
from .risk_engine import RiskEngine
from .model_service import ModelService

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("trustshield")

# ─── Service instances ────────────────────────────────────────────────────────
# Instantiated before the app so they are accessible to routes and tests alike.
model_service = ModelService()
risk_engine = RiskEngine(model_service=model_service)


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
