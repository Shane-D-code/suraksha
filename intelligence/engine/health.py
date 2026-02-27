from pathlib import Path
import json

def health_check():
    base_path = Path(__file__).resolve().parents[2]

    checks = {
    "email_model": (base_path / "models" / "phish_model.joblib").exists(),
    "vectorizer": (base_path / "models" / "tfidf_vectorizer.joblib").exists(),
    "zero_day_model": (base_path / "models" / "zero_day_model.pkl").exists(),
    "config_loaded": (base_path / "config" / "security_policy.json").exists(),
    "nlp_module": (base_path / "intelligence" / "nlp").exists(),
    "web_module": (base_path / "intelligence" / "web").exists()
}

    return {
        "status": "ok" if all(checks.values()) else "degraded",
        "checks": checks
    }