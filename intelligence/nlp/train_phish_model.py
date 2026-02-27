"""
train_phish_model.py

Train and save a calibrated phishing detection model
(TF-IDF + Logistic Regression + Probability Calibration)
"""

import pandas as pd
import joblib
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report

# ---------------- PATHS ---------------- #

BASE_PATH = Path(__file__).resolve().parents[2]

DATA_PATH = BASE_PATH / "data" / "raw" / "emails" / "phishing_email.csv"
MODEL_DIR = BASE_PATH / "models"

MODEL_DIR.mkdir(exist_ok=True)

MODEL_PATH = MODEL_DIR / "phish_model.joblib"
VECTORIZER_PATH = MODEL_DIR / "tfidf_vectorizer.joblib"

# ---------------- LOAD DATA ---------------- #

df = pd.read_csv(DATA_PATH)

# Expect columns:
# - subject
# - body
# - label (0 = safe, 1 = phishing)

# Combine subject and body into text_combined
# Handle NaN values by filling with empty string
df["subject"] = df["subject"].fillna("")
df["body"] = df["body"].fillna("")
df["text_combined"] = df["subject"].astype(str) + " " + df["body"].astype(str)
X = df["text_combined"]
y = df["label"].astype(int)

# ---------------- TRAIN / TEST SPLIT ---------------- #

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ---------------- VECTORIZATION ---------------- #

vectorizer = TfidfVectorizer(
    max_features=30000,
    ngram_range=(1, 2),
    stop_words="english"
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# ---------------- BASE MODEL ---------------- #

base_model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced"
)

# ---------------- CALIBRATION ---------------- #

calibrated_model = CalibratedClassifierCV(
    estimator=base_model,
    method="sigmoid",   # Platt scaling
    cv=5
)

calibrated_model.fit(X_train_vec, y_train)

# ---------------- EVALUATION ---------------- #

y_pred = calibrated_model.predict(X_test_vec)

print("\n📊 Classification Report (Calibrated Model)")
print(classification_report(y_test, y_pred))

# ---------------- SAVE MODELS ---------------- #

joblib.dump(calibrated_model, MODEL_PATH)
joblib.dump(vectorizer, VECTORIZER_PATH)

print("\n✅ Calibrated phishing model trained and saved.")
print(f"Model saved to: {MODEL_PATH}")
print(f"Vectorizer saved to: {VECTORIZER_PATH}")
