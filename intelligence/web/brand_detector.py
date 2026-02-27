import idna
import tldextract
from rapidfuzz import fuzz

HOMOGLYPHS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a"
}

KNOWN_BRANDS = [
    "google", "paypal", "microsoft", "apple",
    "amazon", "facebook", "instagram"
]

FUZZY_THRESHOLD = 85

def normalize_homoglyphs(text: str) -> str:
    for k, v in HOMOGLYPHS.items():
        text = text.replace(k, v)
    return text

def normalize_domain(domain: str) -> str:
    try:
        domain = idna.decode(domain.encode("utf-8"))
    except Exception:
        pass
    domain = domain.lower()
    domain = normalize_homoglyphs(domain)
    return domain

def detect_brand_impersonation(url: str) -> dict:
    extracted = tldextract.extract(url)

    registered_domain = normalize_domain(extracted.registered_domain)
    subdomain = normalize_domain(extracted.subdomain)

    for brand in KNOWN_BRANDS:
        # Legit domain protection
        if registered_domain.endswith(f"{brand}.com"):
            return {
                "impersonation": False,
                "brand": brand,
                "confidence": 0.0
            }

        score_rd = fuzz.partial_ratio(brand, registered_domain)
        score_sd = fuzz.partial_ratio(brand, subdomain)

        best_score = max(score_rd, score_sd)

        if best_score >= FUZZY_THRESHOLD:
            return {
                "impersonation": True,
                "brand": brand,
                "confidence": round(best_score / 100, 2)
            }

    return {
        "impersonation": False,
        "brand": None,
        "confidence": 0.0
    }