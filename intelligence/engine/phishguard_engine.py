from pathlib import Path
import json
import csv
from datetime import datetime, UTC
import tldextract

from intelligence.engine.ml_runner import run_ml, run_meta_model
from intelligence.engine.attribution import build_attributions
from intelligence.web.url_checks import analyze_url
from intelligence.web.html_inspector import detect_login_form
from intelligence.web.brand_detector import detect_brand_impersonation
from intelligence.web.brand_risk import brand_risk_score
from intelligence.nlp.zero_day_detector import get_anomaly_score


# ---------------- BASE PATH ---------------- #

BASE_PATH = Path(__file__).resolve().parents[2]

# ---------------- CONFIG ---------------- #

META_LOG_PATH = BASE_PATH / "data" / "meta_training.csv"

with open(BASE_PATH / "config" / "trusted_domains.json") as f:
    TRUSTED_DOMAINS = json.load(f)

with open(BASE_PATH / "config" / "security_policy.json") as f:
    SECURITY_POLICY = json.load(f)

with open(BASE_PATH / "config" / "thresholds.json") as f:
    THRESHOLDS = json.load(f)


# ---------------- META LOGGER ---------------- #

META_COLUMNS = [
    "risk_score",
    "ml_prob",
    "zero_day_score",
    "sms_risk",
    "brand_impersonation",
    "brand_confidence",
    "login_form",
    "suspicious_url_score",
    "is_trusted_domain",
    "label",
    "source",
    "timestamp"
]


def log_meta_sample(features, label, source):
    row = {
        k: float(features.get(k, 0.0))
        for k in META_COLUMNS
        if k not in ["label", "source", "timestamp"]
    }

    row["label"] = int(label)
    row["source"] = source
    row["timestamp"] = datetime.now(UTC).isoformat()

    file_exists = META_LOG_PATH.exists()

    with open(META_LOG_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=META_COLUMNS)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


# ---------------- SMS HEURISTIC ---------------- #

SMS_URGENCY = ["urgent", "verify", "immediately", "suspended", "locked", "click"]


def analyze_sms(text):
    text = text.lower()
    return min(sum(1 for w in SMS_URGENCY if w in text), 2)


# ---------------- DECISION ---------------- #

def decide_action(score, channel):
    t = THRESHOLDS[channel]

    if score >= t["block"]:
        return "block"
    if score >= t["warn"]:
        return "warn"
    if score >= t["review"]:
        return "review"
    return "allow"


# ---------------- EMAIL ---------------- #

def analyze_email(text):

    # ---- Feature Extraction ---- #

    sms_risk = analyze_sms(text)

    brand_result = detect_brand_impersonation(text)
    brand_risk = brand_risk_score(brand_result)

    zero_day_score = 0.0
    if SECURITY_POLICY.get("enable_zero_day", True):
        try:
            zero_day_score = min(get_anomaly_score(text), 1.0)
        except RuntimeError:
            pass

    ml_result = run_ml(text)
    ml_prob = ml_result["probability"] if ml_result else 0.0

    features = {
        "ml_prob": ml_prob,
        "zero_day_score": zero_day_score,
        "sms_risk": sms_risk,
        "brand_impersonation": round(float(brand_risk), 3),
        "brand_confidence": brand_result.get("confidence", 0.0),
        "login_form": 0,
        "suspicious_url_score": 0,
        "is_trusted_domain": 0
    }

    # ---- Meta Model (Final Authority) ---- #

    meta = run_meta_model(features)
    score = round(meta["probability"], 2) if meta else 0.0

    action = decide_action(score, "email")
    verdict = "phishing" if action == "block" else "safe"

    features["risk_score"] = score

    log_meta_sample(features, int(verdict == "phishing"), "email")

    return {
        "type": "email_or_sms",
        "verdict": verdict,
        "action": action,
        "risk_score": score,
        "confidence": score,  # Step 8: calibrated probability only
        "reasons": build_attributions(features, score),
        "features": features
    }


# ---------------- WEBSITE ---------------- #

def analyze_website(url):

    extracted = tldextract.extract(url)
    domain = extracted.registered_domain.lower()
    is_trusted = domain in TRUSTED_DOMAINS

    url_result = analyze_url(url)
    form_result = detect_login_form(url)
    brand_result = detect_brand_impersonation(url)
    brand_risk = brand_risk_score(brand_result)

    features = {
        "ml_prob": 0.0,
        "zero_day_score": 0.0,
        "sms_risk": 0,
        "brand_impersonation": round(float(brand_risk), 3),
        "brand_confidence": brand_result.get("confidence", 0.0),
        "login_form": int(form_result.get("login_form_detected", False)),
        "suspicious_url_score": url_result.get("score", 0.0),
        "is_trusted_domain": int(is_trusted)
    }

    meta = run_meta_model(features)
    score = round(meta["probability"], 2) if meta else 0.0

    action = decide_action(score, "website")
    verdict = "phishing" if action == "block" else "safe"

    features["risk_score"] = score

    log_meta_sample(features, int(verdict == "phishing"), "website")

    return {
        "type": "website",
        "verdict": verdict,
        "action": action,
        "risk_score": score,
        "confidence": score,  # Step 8 complete
        "reasons": build_attributions(features, score),
        "features": features
    }


# ---------------- ENTRY ---------------- #

def analyze(input_type, payload):
    input_type = input_type.lower().strip()

    if input_type in ["email", "sms", "email_or_sms"]:
        return analyze_email(payload)

    if input_type == "website":
        return analyze_website(payload)

    raise ValueError(f"Unsupported input type: {input_type}")