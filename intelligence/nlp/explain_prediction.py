import joblib
import numpy as np
from pathlib import Path

BASE_PATH = Path(__file__).resolve().parents[2]
MODEL_PATH = BASE_PATH / "models" / "phish_model.joblib"
VECTORIZER_PATH = BASE_PATH / "models" / "tfidf_vectorizer.joblib"

model = None
vectorizer = None

def load_model():
    global model, vectorizer
    if model is None or vectorizer is None:
        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)

def get_average_coefficients(calibrated_model):
    """
    Average coefficients from all calibrated classifiers
    """
    coefs = []
    for clf in calibrated_model.calibrated_classifiers_:
        base_estimator = clf.estimator
        coefs.append(base_estimator.coef_[0])
    return np.mean(coefs, axis=0)

def explain_email(text, top_k=10):
    load_model()

    vec = vectorizer.transform([text])
    probs = model.predict_proba(vec)[0]
    prediction = int(model.predict(vec)[0])

    feature_names = vectorizer.get_feature_names_out()

    # 🔥 FIX: Handle calibrated model correctly
    if hasattr(model, "calibrated_classifiers_"):
        coefs = get_average_coefficients(model)
    else:
        coefs = model.coef_[0]

    weighted_features = vec.toarray()[0] * coefs
    top_indices = np.argsort(weighted_features)[-top_k:][::-1]

    reasons = [
        (feature_names[i], float(weighted_features[i]))
        for i in top_indices
        if weighted_features[i] > 0
    ]

    return {
        "prediction": prediction,
        "phishing_probability": float(probs[1]),
        "top_reasons": reasons
    }