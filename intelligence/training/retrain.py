import pandas as pd
import joblib
import json
from pathlib import Path
from datetime import datetime, UTC

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.calibration import CalibratedClassifierCV

# ---------------- PATHS ---------------- #

BASE_PATH = Path(__file__).resolve().parents[2]

DATA_PATH = BASE_PATH / "data" / "meta_training.csv"
MODEL_DIR = BASE_PATH / "models"
CONFIG_DIR = BASE_PATH / "config"

MODEL_DIR.mkdir(exist_ok=True)

SIGNALS_PATH = CONFIG_DIR / "signals.json"
THRESHOLDS_PATH = CONFIG_DIR / "thresholds.json"
ACTIVE_MODELS_PATH = MODEL_DIR / "active_models.json"

# ---------------- LOAD DATA ---------------- #

if not DATA_PATH.exists():
    raise FileNotFoundError("meta_training.csv not found")

df = pd.read_csv(DATA_PATH, engine="python", on_bad_lines="skip")

if "risk_score" not in df.columns:
    raise ValueError(
        "risk_score not found. Run engine after Step 9 engine update."
    )

FEATURE_COLS = [
    "ml_prob",
    "zero_day_score",
    "sms_risk",
    "brand_impersonation",
    "brand_confidence",
    "login_form",
    "suspicious_url_score",
    "is_trusted_domain"
]

REQUIRED_COLS = FEATURE_COLS + ["risk_score", "label", "source"]

for col in REQUIRED_COLS:
    if col not in df.columns:
        df[col] = 0

df = df[REQUIRED_COLS]
df = df.apply(pd.to_numeric, errors="coerce")
df = df.dropna(subset=["label", "risk_score"])
df = df.fillna(0)

if df.empty:
    raise ValueError("No valid training data available")

X = df[FEATURE_COLS]
y = df["label"].astype(int)

if y.nunique() < 2:
    raise ValueError("Need both phishing and safe samples")

# ---------------- TRAIN / TEST (COLD-START SAFE) ---------------- #

if y.value_counts().min() < 2:
    print("⚠️  Not enough samples for stratified split. Training on full dataset.")
    X_train, y_train = X, y
else:
    X_train, _, y_train, _ = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

# ---------------- CALIBRATED PHISH MODEL ---------------- #

base_lr = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    solver="lbfgs"
)

calibrated_lr = CalibratedClassifierCV(
    base_estimator=base_lr,
    method="sigmoid",
    cv=3
)

phish_pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("clf", calibrated_lr)
])

phish_pipeline.fit(X_train, y_train)

# ---------------- LEARN SIGNAL WEIGHTS (FROM BASE LR) ---------------- #

calibrated = phish_pipeline.named_steps["clf"]
base_estimator = calibrated.calibrated_classifiers_[0].estimator

coefs = base_estimator.coef_[0]
feature_weights = dict(zip(FEATURE_COLS, coefs))

max_abs = max(abs(v) for v in feature_weights.values()) or 1.0

normalized_weights = {
    k: round(float(v / max_abs), 3)
    for k, v in feature_weights.items()
}

learned_signals = {
    "email": normalized_weights,
    "website": normalized_weights
}

with open(SIGNALS_PATH, "w", encoding="utf-8") as f:
    json.dump(learned_signals, f, indent=4)

print("🧠 Learned signal weights saved → config/signals.json")

# ---------------- THRESHOLD CALIBRATION ---------------- #

def calibrate_thresholds(channel_df):
    phishing = channel_df[channel_df["label"] == 1]
    safe = channel_df[channel_df["label"] == 0]

    if phishing.empty or safe.empty:
        return None

    review = round(safe["risk_score"].quantile(0.90), 2)
    warn   = round(phishing["risk_score"].quantile(0.50), 2)
    block  = round(phishing["risk_score"].quantile(0.80), 2)

    return {
        "review": min(review, warn - 0.05),
        "warn": min(warn, block - 0.05),
        "block": block
    }

thresholds = {}

for channel in ["email", "website"]:
    channel_df = df[df["source"] == channel]
    if len(channel_df) >= 10:
        t = calibrate_thresholds(channel_df)
        if t:
            thresholds[channel] = t

if thresholds:
    with open(THRESHOLDS_PATH, "w", encoding="utf-8") as f:
        json.dump(thresholds, f, indent=4)
    print("🎯 Thresholds auto-calibrated → config/thresholds.json")

# ---------------- ZERO-DAY MODEL ---------------- #

safe_samples = X[y == 0]

anomaly_model = None
anomaly_versioned = None

if len(safe_samples) >= 5:
    anomaly_model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42
    )
    anomaly_model.fit(safe_samples)
else:
    print("⚠️  Too few safe samples for anomaly model. Skipping.")

# ---------------- SAVE MODELS ---------------- #

timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

phish_versioned = MODEL_DIR / f"phish_model_{timestamp}.joblib"
joblib.dump(phish_pipeline, phish_versioned)

if anomaly_model is not None:
    anomaly_versioned = MODEL_DIR / f"zero_day_model_{timestamp}.joblib"
    joblib.dump(anomaly_model, anomaly_versioned)

active_models = {
    "phish_model": phish_versioned.name,
    "zero_day_model": anomaly_versioned.name if anomaly_versioned else None,
    "timestamp": timestamp
}

with open(ACTIVE_MODELS_PATH, "w", encoding="utf-8") as f:
    json.dump(active_models, f, indent=4)

print("✅ Retraining complete with versioning")
print(f"📦 Active phishing model → {active_models['phish_model']}")
print(f"📦 Active zero-day model → {active_models['zero_day_model']}")
print(f"🕒 Timestamp: {timestamp}")