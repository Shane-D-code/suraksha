from pathlib import Path
import json
from joblib import load

# ---------------- PATHS ---------------- #

BASE_PATH = Path(__file__).resolve().parents[2]
MODEL_DIR = BASE_PATH / "models"
ACTIVE_MODELS_PATH = MODEL_DIR / "active_models.json"

_text_model = None
_meta_model = None

# ---------------- HELPERS ---------------- #

def load_active_phish_model():
    """
    Loads the currently active meta phishing model.
    """
    global _meta_model

    if _meta_model is not None:
        return _meta_model

    if not ACTIVE_MODELS_PATH.exists():
        raise FileNotFoundError("active_models.json not found")

    with open(ACTIVE_MODELS_PATH) as f:
        active = json.load(f)

    model_name = active.get("phish_model")
    if not model_name:
        raise ValueError("Active phishing model not defined")

    model_path = MODEL_DIR / model_name
    _meta_model = load(model_path)
    return _meta_model


def load_text_model():
    """
    Optional NLP phishing model (text-based).
    """
    global _text_model

    text_model_path = MODEL_DIR / "text_model.joblib"
    if not text_model_path.exists():
        raise FileNotFoundError("Text ML model not found")

    if _text_model is None:
        _text_model = load(text_model_path)

    return _text_model

# ---------------- ML RUNNERS ---------------- #

def run_ml(text: str):
    """
    Optional text ML.
    Failure returns None.
    """
    try:
        model = load_text_model()
        prob = float(model.predict_proba([text])[0][1])
        pred = int(prob >= 0.5)

        return {
            "prediction": pred,
            "probability": round(prob, 3)
        }
    except Exception:
        return None


def run_meta_model(features: dict):
    """
    Final learned risk scoring model.
    This decides the risk score.
    """
    try:
        model = load_active_phish_model()
    except Exception:
        return None

    feature_order = [
        "ml_prob",
        "zero_day_score",
        "sms_risk",
        "brand_impersonation",
        "brand_confidence",
        "login_form",
        "suspicious_url_score",
        "is_trusted_domain"
    ]

    import pandas as pd
    X = pd.DataFrame([features], columns=feature_order)

    try:
        prob = float(model.predict_proba(X)[0][1])
        pred = int(prob >= 0.5)

        return {
            "prediction": pred,
            "probability": round(prob, 3)
        }
    except Exception:
        return None