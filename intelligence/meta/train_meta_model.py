import pandas as pd
import joblib
from pathlib import Path
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

DATA_PATH = Path("data/meta_training.csv")
MODEL_OUT = Path("models/meta_model.joblib")

df = pd.read_csv(DATA_PATH)

# Separate features and label
X = df.drop(columns=["label", "source", "timestamp"])
y = df["label"]

# Train/validation split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

joblib.dump(model, MODEL_OUT)

print("Meta-model trained and saved.")
print("Train accuracy:", model.score(X_train, y_train))
print("Test accuracy:", model.score(X_test, y_test))