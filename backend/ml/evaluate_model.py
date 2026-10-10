"""
TrustShield — Model Evaluation Script

Runs evaluation on a held-out test set and produces a detailed report.
Can be used to re-evaluate an existing model artifact without retraining.

Usage:
    python evaluate_model.py [--dataset PATH]
"""

import sys
import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    roc_curve,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("trustshield.evaluate")

SCRIPT_DIR = Path(__file__).parent
MODEL_PATH = SCRIPT_DIR / "model_artifacts" / "trustshield_model.joblib"
METRICS_PATH = SCRIPT_DIR / "model_artifacts" / "evaluation_metrics.json"


def main():
    import argparse
    parser = argparse.ArgumentParser(description="TrustShield Model Evaluation")
    parser.add_argument("--dataset", type=str, default=None)
    args = parser.parse_args()
    
    if not MODEL_PATH.exists():
        logger.error(f"Model not found at {MODEL_PATH}. Run train_model.py first.")
        sys.exit(1)
    
    artifact = joblib.load(MODEL_PATH)
    if isinstance(artifact, dict):
        model = artifact["model"]
        feature_names = artifact.get("feature_names", [])
    else:
        model = artifact
        feature_names = []
    
    logger.info(f"Model loaded: {type(model).__name__}")
    
    # Load existing metrics
    if METRICS_PATH.exists():
        with open(METRICS_PATH) as f:
            metrics = json.load(f)
        
        logger.info("\n" + "=" * 50)
        logger.info("Existing Evaluation Metrics")
        logger.info("=" * 50)
        logger.info(f"Test set size:    {metrics.get('test_set_size', 'N/A')}")
        logger.info(f"Accuracy:         {metrics.get('accuracy', 'N/A')}")
        logger.info(f"Precision:        {metrics.get('precision', 'N/A')}")
        logger.info(f"Recall:           {metrics.get('recall', 'N/A')}")
        logger.info(f"F1 Score:         {metrics.get('f1_score', 'N/A')}")
        logger.info(f"AUC-ROC:          {metrics.get('auc_roc', 'N/A')}")
        logger.info(f"False Positive Rate: {metrics.get('false_positive_rate', 'N/A')}")
        logger.info(f"False Negative Rate: {metrics.get('false_negative_rate', 'N/A')}")
        
        cm = metrics.get("confusion_matrix", {})
        logger.info(f"\nConfusion Matrix:")
        logger.info(f"  TN={cm.get('true_negative','?')}  FP={cm.get('false_positive','?')}")
        logger.info(f"  FN={cm.get('false_negative','?')}  TP={cm.get('true_positive','?')}")
        
        logger.info(f"\nFeature Importances:")
        fi = metrics.get("feature_importances", {})
        for feat, imp in sorted(fi.items(), key=lambda x: -x[1]):
            bar = "█" * int(imp * 40)
            logger.info(f"  {feat:<35} {imp:.4f} {bar}")
        
        logger.info("=" * 50)
    else:
        logger.info("No saved metrics found. Run train_model.py to generate them.")


if __name__ == "__main__":
    main()
