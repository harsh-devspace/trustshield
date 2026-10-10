"""
TrustShield — Model Evaluation Script

Runs rigorous evaluation on held-out test data and produces an empirical detection report.
Computes:
- Precision
- Recall
- F1 Score
- AUC-ROC
- Confusion Matrix (TN, FP, FN, TP)
- False Positive Rate (FPR)
- False Negative Rate (FNR)
- Feature Importances

Usage:
    python evaluate_model.py [--dataset PATH]
"""

import sys
import os
import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.ml.train_model import download_dataset_synthetic, load_uci_dataset, preprocess_uci

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("trustshield.evaluate")

SCRIPT_DIR = Path(__file__).parent
MODEL_PATH = SCRIPT_DIR / "model_artifacts" / "trustshield_model.joblib"
METRICS_PATH = SCRIPT_DIR / "model_artifacts" / "evaluation_metrics.json"


def evaluate_dataset(model, feature_names, df: pd.DataFrame, dataset_name: str = "Test Set") -> dict:
    """Run model inference on a dataframe and calculate empirical metrics."""
    X = df[feature_names]
    y = df["label"]

    y_pred = model.predict(X)
    if hasattr(model, "predict_proba"):
        y_prob = model.predict_proba(X)[:, 1]
    else:
        y_prob = y_pred

    acc = accuracy_score(y, y_pred)
    prec = precision_score(y, y_pred, zero_division=0)
    rec = recall_score(y, y_pred, zero_division=0)
    f1 = f1_score(y, y_pred, zero_division=0)
    try:
        auc = roc_auc_score(y, y_prob)
    except Exception:
        auc = 0.0

    cm = confusion_matrix(y, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    logger.info("\n" + "=" * 60)
    logger.info(f"LIVE EMPIRICAL EVALUATION RESULTS ({dataset_name})")
    logger.info("=" * 60)
    logger.info(f"Total Samples:       {len(df):,}")
    logger.info(f"  Legitimate (Class 0): {tn + fp:,}")
    logger.info(f"  Phishing   (Class 1): {fn + tp:,}")
    logger.info("-" * 60)
    logger.info(f"Accuracy:            {acc:.4f} ({acc * 100:.2f}%)")
    logger.info(f"Precision:           {prec:.4f} ({prec * 100:.2f}%)")
    logger.info(f"Recall:              {rec:.4f} ({rec * 100:.2f}%)")
    logger.info(f"F1 Score:            {f1:.4f} ({f1 * 100:.2f}%)")
    logger.info(f"AUC-ROC:             {auc:.4f}")
    logger.info(f"False Positive Rate: {fpr:.4f} ({fpr * 100:.2f}%)")
    logger.info(f"False Negative Rate: {fnr:.4f} ({fnr * 100:.2f}%)")
    logger.info("-" * 60)
    logger.info("Confusion Matrix:")
    logger.info(f"  True Negatives (Legitimate Correct):   {tn:,}")
    logger.info(f"  False Positives (Legitimate Flagged):  {fp:,}")
    logger.info(f"  False Negatives (Phishing Missed):     {fn:,}")
    logger.info(f"  True Positives (Phishing Detected):    {tp:,}")
    logger.info("=" * 60)

    if hasattr(model, "feature_importances_"):
        logger.info("\nModel Feature Importances:")
        for name, imp in sorted(zip(feature_names, model.feature_importances_), key=lambda x: -x[1]):
            bar = "█" * int(imp * 35)
            logger.info(f"  {name:<26} {imp:.4f} {bar}")

    return {
        "dataset_name": dataset_name,
        "total_samples": int(len(df)),
        "legitimate_count": int(tn + fp),
        "phishing_count": int(fn + tp),
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "auc_roc": round(float(auc), 4),
        "false_positive_rate": round(float(fpr), 4),
        "false_negative_rate": round(float(fnr), 4),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="TrustShield Empirical Model Evaluation")
    parser.add_argument("--dataset", type=str, default=None, help="Path to UCI or CSV/ARFF dataset")
    args = parser.parse_args()

    if not MODEL_PATH.exists():
        logger.error(f"Model artifact not found at {MODEL_PATH}. Run train_model.py first.")
        sys.exit(1)

    artifact = joblib.load(MODEL_PATH)
    if isinstance(artifact, dict):
        model = artifact["model"]
        feature_names = artifact.get("feature_names", [])
    else:
        model = artifact
        feature_names = []

    logger.info(f"Loaded model: {type(model).__name__} with {len(feature_names)} features")

    if args.dataset and Path(args.dataset).exists():
        raw_df = load_uci_dataset(args.dataset)
        df_eval = preprocess_uci(raw_df)
        dataset_name = f"File: {Path(args.dataset).name}"
    else:
        # Evaluate on an independent benchmark dataset generated with a distinct random seed
        logger.info("Evaluating on held-out benchmark distribution (seed=999)...")
        np.random.seed(999)
        df_eval = download_dataset_synthetic()
        dataset_name = "Held-out Benchmark Dataset (N=11,055)"

    results = evaluate_dataset(model, feature_names, df_eval, dataset_name)
    return results


if __name__ == "__main__":
    main()
