import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

DATA_PATH = "data/raw/emails/phishing_email.csv"

df = pd.read_csv(DATA_PATH)

X = df["text_combined"]
y = df["label"]

vectorizer = TfidfVectorizer(
    max_features=30000,
    ngram_range=(1, 2),
    stop_words="english"
)

X_vec = vectorizer.fit_transform(X)

model = LogisticRegression(max_iter=1000)
model.fit(X_vec, y)

joblib.dump(model, "intelligence/nlp/phish_model.joblib")
joblib.dump(vectorizer, "intelligence/nlp/tfidf_vectorizer.joblib")

print("Model and vectorizer saved successfully.")
