"""
TrustShield — Model Service

Loads the trained scikit-learn model artifact from disk and provides
prediction functionality. Falls back gracefully when the model is not available.

Design decisions:
- The model artifact is loaded once at startup and cached in memory.
- If the artifact file is missing, the service degrades gracefully to heuristics-only mode.
- Model predictions are probabilities; they are converted to a 0–100 risk contribution.
- The model's phishing probability is NOT presented as a calibrated fraud probability.
"""

from __future__ import annotations
import os
import logging
import json
from pathlib import Path
from typing import Optional, Dict, Any, List

import joblib
import numpy as np

logger = logging.getLogger("trustshield.model")

# ─── Paths ────────────────────────────────────────────────────────────────────
_BASE_DIR = Path(__file__).parent.parent  # trustshield/backend/
MODEL_ARTIFACTS_DIR = _BASE_DIR / "ml" / "model_artifacts"
MODEL_PATH = MODEL_ARTIFACTS_DIR / "trustshield_model.joblib"
METRICS_PATH = MODEL_ARTIFACTS_DIR / "evaluation_metrics.json"
SCHEMA_PATH = MODEL_ARTIFACTS_DIR / "feature_schema.json"


class ModelService:
    """
    Manages the ML model lifecycle: loading, prediction, and metadata.
    Thread-safe for read operations (joblib models are read-only after loading).
    """

    def __init__(self):
        self._model = None
        self._feature_names: List[str] = []
        self._metrics: Dict[str, Any] = {}
        self._schema: Dict[str, Any] = {}
        self._trained_at: Optional[str] = None
        self._model_type: str = "unknown"

    def load_model(self) -> bool:
        """
        Load the model artifact from disk.
        Returns True if successful, False if the file is missing or corrupt.
        """
        if not MODEL_PATH.exists():
            logger.warning(f"Model artifact not found at {MODEL_PATH}. Run train_model.py first.")
            return False

        try:
            artifact = joblib.load(MODEL_PATH)
            # The artifact is a dict containing the model and metadata
            if isinstance(artifact, dict):
                self._model = artifact.get("model")
                self._feature_names = artifact.get("feature_names", [])
                self._model_type = artifact.get("model_type", "RandomForestClassifier")
                self._trained_at = artifact.get("trained_at")
            else:
                # Legacy format: artifact is the model directly
                self._model = artifact
                self._model_type = type(artifact).__name__

            logger.info(f"Model loaded: {self._model_type} with {len(self._feature_names)} features")
        except Exception as e:
            logger.error(f"Failed to load model: {e}", exc_info=True)
            self._model = None
            return False

        # Load evaluation metrics
        if METRICS_PATH.exists():
            try:
                with open(METRICS_PATH) as f:
                    self._metrics = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load metrics: {e}")

        # Load feature schema
        if SCHEMA_PATH.exists():
            try:
                with open(SCHEMA_PATH) as f:
                    self._schema = json.load(f)
                    if not self._feature_names:
                        self._feature_names = self._schema.get("feature_names", [])
            except Exception as e:
                logger.warning(f"Could not load feature schema: {e}")

        return True

    def is_loaded(self) -> bool:
        return self._model is not None

    def predict(self, features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Run ML prediction on a feature dict.

        Returns:
            dict with keys: phishing_probability (0.0–1.0), predicted_class (0 or 1)
            None if model is not loaded or prediction fails.
        """
        if not self.is_loaded():
            return None

        try:
            # Build feature vector in the correct order
            if self._feature_names:
                feature_vector = [features.get(f, 0) for f in self._feature_names]
            else:
                # Fall back to feature dict values order
                feature_vector = list(features.values())

            X = np.array(feature_vector, dtype=float).reshape(1, -1)

            # Get probability
            if hasattr(self._model, "predict_proba"):
                proba = self._model.predict_proba(X)[0]
                # Class 1 = phishing
                phishing_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
            else:
                # Model without probability support — use binary prediction
                pred = int(self._model.predict(X)[0])
                phishing_prob = float(pred)

            predicted_class = int(phishing_prob >= 0.5)

            return {
                "phishing_probability": phishing_prob,
                "predicted_class": predicted_class,
            }

        except Exception as e:
            logger.error(f"Prediction error: {e}", exc_info=True)
            return None

    def get_model_info(self) -> Dict[str, Any]:
        """Return model metadata for the /model-info endpoint."""
        return {
            "model_type": self._model_type,
            "model_available": self.is_loaded(),
            "features": self._feature_names,
            "training_dataset": self._metrics.get(
                "dataset",
                "UCI Phishing Websites Dataset (or equivalent)"
            ),
            "evaluation_metrics": {
                k: v for k, v in self._metrics.items()
                if k not in ("dataset",)
            },
            "trained_at": self._trained_at,
            "notes": (
                "The phishing_probability score is a model output, not a calibrated "
                "fraud probability. Risk scores combine ML predictions with heuristic signals."
            ),
        }
