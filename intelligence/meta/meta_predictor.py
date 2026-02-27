import joblib
from pathlib import Path

MODEL_PATH = Path("models/meta_model.joblib")

model = joblib.load(MODEL_PATH)

def meta_predict(features: dict) -> float:
    X = [[features[k] for k in sorted(features.keys())]]
    prob = model.predict_proba(X)[0][1]
    return float(prob)