from pathlib import Path

BASE_PATH = Path(__file__).resolve().parents[1]
PHISH_MODEL = BASE_PATH / "models" / "phish_model.joblib"
VECTORIZER = BASE_PATH / "models" / "tfidf_vectorizer.joblib"