import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update",
    "bank", "signin", "confirm", "password"
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq"]

def analyze_url(url):
    reasons = []
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if len(url) > 75:
        reasons.append("Very long URL")

    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
        reasons.append("IP address used instead of domain")

    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            reasons.append(f"Contains keyword: {word}")

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            reasons.append(f"Suspicious TLD: {tld}")

    score = len(reasons)
    verdict = "phishing" if score >= 2 else "safe"

    return {
        "url": url,
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons
    }

if __name__ == "__main__":
    test_urls = [
        "https://accounts.google.com",
        "https://secure-google-login.verify-user.com",
        "https://bankofamerica.com",
        "http://secure-login-verify-account.tk"
    ]

    for u in test_urls:
        print(analyze_url(u))