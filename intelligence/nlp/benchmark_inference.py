import time
import joblib

MODEL_PATH = "intelligence/nlp/phish_model.joblib"
VECTORIZER_PATH = "intelligence/nlp/tfidf_vectorizer.joblib"

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

sample_text = "Urgent! Verify your account immediately."

start = time.time()
vec = vectorizer.transform([sample_text])
pred = model.predict(vec)
end = time.time()

print("Prediction:", pred[0])
print("Inference time (ms):", (end - start) * 1000)