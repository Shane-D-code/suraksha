import json
import pandas as pd
import subprocess
from pathlib import Path
from datetime import datetime, UTC, timedelta

# ---------------- PATHS ---------------- #

BASE_PATH = Path(__file__).resolve().parents[2]

DATA_PATH = BASE_PATH / "data" / "meta_training.csv"
MODEL_DIR = BASE_PATH / "models"
ACTIVE_MODELS_PATH = MODEL_DIR / "active_models.json"

RETRAIN_SCRIPT = BASE_PATH / "intelligence" / "training" / "retrain.py"

# ---------------- POLICY ---------------- #

MIN_NEW_SAMPLES = 30
MIN_CLASS_COUNT = 5
COOLDOWN_HOURS = 1

# ---------------- HELPERS ---------------- #

def load_last_training_time():
    if not ACTIVE_MODELS_PATH.exists():
        return None

    with open(ACTIVE_MODELS_PATH) as f:
        active = json.load(f)

    ts = active.get("timestamp")
    if not ts:
        return None

    return datetime.strptime(ts, "%Y%m%d_%H%M%S").replace(tzinfo=UTC)

def should_retrain(df, last_trained_at):
    if last_trained_at:
        if datetime.now(UTC) - last_trained_at < timedelta(hours=COOLDOWN_HOURS):
            print("⏳ Cooldown active. Skipping retrain.")
            return False

    if len(df) < MIN_NEW_SAMPLES:
        print("📉 Not enough total samples yet.")
        return False

    counts = df["label"].value_counts()

    if counts.min() < MIN_CLASS_COUNT:
        print("⚠️ Class imbalance too high. Skipping retrain.")
        return False

    return True

# ---------------- MAIN ---------------- #

def main():
    if not DATA_PATH.exists():
        print("❌ meta_training.csv not found")
        return

    df = pd.read_csv(DATA_PATH, engine="python", on_bad_lines="skip")

    if "label" not in df.columns:
        print("❌ No labels found")
        return

    last_trained_at = load_last_training_time()

    if not should_retrain(df, last_trained_at):
        return

    print("🚀 Conditions met. Starting retraining...")
    subprocess.run(["python", str(RETRAIN_SCRIPT)], check=True)
    print("✅ Auto-retraining finished")

if __name__ == "__main__":
    main()