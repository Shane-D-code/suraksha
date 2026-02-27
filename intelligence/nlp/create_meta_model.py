"""
Script to create the meta model for PhishGuard hybrid detection.
This generates the calibrated meta model and active_models.json.
"""
import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.calibration import CalibratedClassifierCV

# Create sample meta training data
# Features: ml_prob, zero_day_score, sms_risk, brand_impersonation, brand_confidence, 
#          login_form, suspicious_url_score, is_trusted_domain

# High risk samples (phishing)
high_risk_samples = [
    [0.9, 0.8, 2, 0.9, 0.9, 1, 0.8, 0],  # High ML + anomaly + brand + URL
    [0.85, 0.7, 2, 0.85, 0.85, 1, 0.7, 0],
    [0.95, 0.9, 1, 0.8, 0.8, 0, 0.9, 0],
    [0.8, 0.6, 2, 0.9, 0.9, 1, 0.6, 0],
    [0.88, 0.75, 1, 0.85, 0.85, 1, 0.75, 0],
]

# Medium risk samples (suspicious)
medium_risk_samples = [
    [0.5, 0.4, 1, 0.5, 0.5, 0, 0.5, 0],  # Medium ML + some signals
    [0.4, 0.5, 1, 0.4, 0.4, 0, 0.4, 0],
    [0.6, 0.3, 0, 0.6, 0.6, 0, 0.6, 0],
    [0.45, 0.45, 0, 0.45, 0.45, 0, 0.45, 0],
    [0.55, 0.35, 1, 0.5, 0.5, 0, 0.5, 0],
]

# Low risk / safe samples
safe_samples = [
    [0.1, 0.1, 0, 0.1, 0.1, 0, 0.1, 1],  # Trusted domain
    [0.05, 0.05, 0, 0.0, 0.0, 0, 0.05, 1],
    [0.15, 0.1, 0, 0.1, 0.1, 0, 0.1, 1],
    [0.08, 0.08, 0, 0.05, 0.05, 0, 0.08, 1],
    [0.12, 0.12, 0, 0.08, 0.08, 0, 0.1, 1],
    [0.2, 0.15, 0, 0.1, 0.1, 0, 0.15, 0],  # Low ML, no other signals
    [0.18, 0.12, 0, 0.08, 0.08, 0, 0.12, 0],
    [0.22, 0.18, 0, 0.12, 0.12, 0, 0.15, 0],
    [0.25, 0.2, 0, 0.1, 0.1, 0, 0.2, 0],
    [0.28, 0.22, 0, 0.15, 0.15, 0, 0.18, 0],
]

# Combine data
X = np.array(high_risk_samples + medium_risk_samples + safe_samples)
y = np.array([1]*len(high_risk_samples) + [1]*len(medium_risk_samples) + [0]*len(safe_samples))

feature_names = [
    "ml_prob", "zero_day_score", "sms_risk", "brand_impersonation",
    "brand_confidence", "login_form", "suspicious_url_score", "is_trusted_domain"
]

# Create meta model (Logistic Regression with calibration)
base_model = LogisticRegression(max_iter=1000, C=1.0, random_state=42)
calibrated_model = CalibratedClassifierCV(base_model, cv=3)
calibrated_model.fit(X, y)

# Save model
models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "models")
os.makedirs(models_dir, exist_ok=True)

model_path = os.path.join(models_dir, "meta_phish_model.joblib")
joblib.dump(calibrated_model, model_path)
print(f"✅ Meta model saved to: {model_path}")

# Create active_models.json
active_models = {
    "phish_model": "meta_phish_model.joblib",
    "text_model": "phish_model.joblib"
}

active_models_path = os.path.join(models_dir, "active_models.json")
with open(active_models_path, 'w') as f:
    json.dump(active_models, f, indent=2)
print(f"✅ Active models config saved to: {active_models_path}")

# Test the meta model
print("\n📊 Meta Model Test Results:")

test_cases = [
    {"name": "Phishing (high ML + brand)", "features": [0.9, 0.8, 2, 0.9, 0.9, 1, 0.8, 0]},
    {"name": "Suspicious (medium)", "features": [0.5, 0.4, 1, 0.5, 0.5, 0, 0.5, 0]},
    {"name": "Safe (trusted domain)", "features": [0.1, 0.1, 0, 0.1, 0.1, 0, 0.1, 1]},
]

for tc in test_cases:
    X_test = pd.DataFrame([tc["features"]], columns=feature_names)
    prob = calibrated_model.predict_proba(X_test)[0][1]
    print(f"   {tc['name']} → {prob:.3f} ({'PHISHING' if prob > 0.5 else 'SAFE'})")

