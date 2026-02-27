"""
Phishing Predictor - ML-based threat detection for the PhishGuard API.
This module provides both ML-based and rule-based phishing detection.
"""
import os
import re
from typing import Dict, Any, Optional

# Try to load ML model, fall back to rule-based if not available
ML_MODEL_AVAILABLE = False
model = None
vectorizer = None

try:
    import joblib
    from pathlib import Path
    
    # Look for models in the project root models/ directory
    BASE_PATH = Path(__file__).resolve().parents[2]
    MODEL_PATH = BASE_PATH / "models" / "phish_model.joblib"
    VECTORIZER_PATH = BASE_PATH / "models" / "tfidf_vectorizer.joblib"
    
    if MODEL_PATH.exists() and VECTORIZER_PATH.exists():
        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)
        ML_MODEL_AVAILABLE = True
        print(f"[PhishGuard] ML model loaded successfully from {MODEL_PATH}")
    else:
        # Fallback to local directory
        MODEL_PATH = os.path.join(os.path.dirname(__file__), "phish_model.joblib")
        VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "tfidf_vectorizer.joblib")
        if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
            model = joblib.load(MODEL_PATH)
            vectorizer = joblib.load(VECTORIZER_PATH)
            ML_MODEL_AVAILABLE = True
            print("[PhishGuard] ML model loaded successfully from local directory")
except Exception as e:
    print(f"[PhishGuard] ML model not available, using rule-based detection: {e}")


class PhishingPredictor:
    """
    Main predictor class for phishing detection.
    Tries ML model first, falls back to rule-based detection.
    """
    
    def __init__(self):
        self.phishing_patterns = [
            r'verify.*account',
            r'account.*suspended',
            r'urgent.*action',
            r'click.*immediately',
            r'confirm.*identity',
            r'reset.*password',
            r'unusual.*activity',
            r'update.*payment',
            r'limited.*time',
            r'claim.*prize',
            r'you.*won',
            r'congratulations',
            r'security.*alert',
            r'unauthorized.*access'
        ]
        
        self.suspicious_keywords = [
            'verify', 'urgent', 'suspended', 'immediately', 'confirm',
            'identity', 'reset', 'password', 'unusual', 'activity',
            'update', 'payment', 'limited', 'time', 'prize', 'winner',
            'claim', 'congratulations', 'act', 'now', 'alert', 'warning',
            'blocked', 'locked', 'unauthorized', 'fraud', 'bank',
            'credit', 'account', 'login', 'secure'
        ]
        
        self.brand_keywords = [
            'paypal', 'amazon', 'netflix', 'apple', 'microsoft',
            'google', 'facebook', 'instagram', 'bank', 'irs',
            'fedex', 'ups', 'dhl', 'usps', 'delivery'
        ]
    
    def predict(self, text: str, url: Optional[str] = None, html: Optional[str] = None) -> Dict[str, Any]:
        """
        Predict if content is phishing.
        
        Args:
            text: Text content to analyze
            url: Optional URL to analyze
            html: Optional HTML content to analyze
            
        Returns:
            Dictionary with prediction results
        """
        # Try ML model first
        if ML_MODEL_AVAILABLE and model and vectorizer and text:
            try:
                # Vectorize the text first, then predict
                text_vec = vectorizer.transform([text])
                prob = model.predict_proba(text_vec)[0][1]
                pred = model.predict(text_vec)[0]
                
                return {
                    'score': float(prob),
                    'is_phishing': bool(pred),
                    'confidence': float(prob),
                    'method': 'ml'
                }
            except Exception as e:
                print(f"ML prediction failed: {e}")
        
        # Fall back to rule-based detection
        return self._rule_based_predict(text, url, html)
    
    def _rule_based_predict(self, text: str, url: Optional[str], html: Optional[str]) -> Dict[str, Any]:
        """Rule-based phishing detection."""
        score = 0.0
        reasons = []
        
        # Analyze URL
        if url:
            url_lower = url.lower()
            
            # Check for suspicious patterns in URL
            for pattern in self.phishing_patterns:
                if re.search(pattern, url_lower):
                    score += 0.15
                    reasons.append(f"Suspicious URL pattern: {pattern}")
            
            # Check for IP address in URL
            ip_pattern = r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.search(ip_pattern, url):
                score += 0.2
                reasons.append("URL contains IP address instead of domain")
            
            # Check for excessive subdomains
            if url_lower.count('.') > 3:
                score += 0.1
                reasons.append("Excessive subdomains in URL")
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
            if any(url_lower.endswith(tld) for tld in suspicious_tlds):
                score += 0.15
                reasons.append("Suspicious free TLD")
            
            # Check for brand impersonation
            for brand in self.brand_keywords:
                if brand in url_lower:
                    score += 0.1
                    reasons.append(f"Brand keyword in URL: {brand}")
        
        # Analyze text content
        if text:
            text_lower = text.lower()
            
            # Keyword density analysis
            keyword_count = sum(1 for kw in self.suspicious_keywords if kw in text_lower)
            keyword_density = keyword_count / max(len(text.split()), 1)
            score += min(keyword_density * 3, 0.3)
            
            if keyword_count > 3:
                reasons.append(f"High number of suspicious keywords: {keyword_count}")
            
            # Pattern matching
            for pattern in self.phishing_patterns[:5]:  # Top 5 patterns
                if re.search(pattern, text_lower):
                    score += 0.12
                    if f"Pattern: {pattern}" not in reasons:
                        reasons.append(f"Found phishing pattern")
            
            # Urgency language
            urgency_words = ['urgent', 'immediately', '24 hours', '48 hours', 'suspended', 'terminated']
            urgency_count = sum(1 for word in urgency_words if word in text_lower)
            if urgency_count > 0:
                score += urgency_count * 0.08
                reasons.append("Urgency language detected")
        
        # Analyze HTML if provided
        if html:
            html_lower = html.lower()
            
            # Check for password fields
            if 'type="password"' in html_lower or "type='password'" in html_lower:
                score += 0.15
                reasons.append("Password input field detected")
            
            # Check for hidden inputs
            if 'type="hidden"' in html_lower:
                score += 0.1
                reasons.append("Hidden input fields detected")
            
            # Check for external forms
            if '<form' in html_lower and 'action="http' in html_lower:
                score += 0.1
                reasons.append("Form submits to external URL")
        
        # Normalize score
        score = min(score, 1.0)
        
        return {
            'score': round(score, 3),
            'is_phishing': score >= 0.5,
            'confidence': round(score if score >= 0.5 else 1 - score, 3),
            'reasons': reasons[:5],  # Top 5 reasons
            'method': 'rule_based'
        }


def predict_email(text: str) -> Dict[str, Any]:
    """Legacy function for email prediction."""
    predictor = PhishingPredictor()
    result = predictor.predict(text)
    return {
        "is_phishing": result['is_phishing'],
        "confidence": result['confidence']
    }


if __name__ == "__main__":
    predictor = PhishingPredictor()
    
    test_cases = [
        "Your invoice is attached. Please review.",
        "Urgent! Verify your account immediately or it will be suspended.",
        "https://192.168.1.1/login.php",
        "https://paypal-verify-account.xyz/login"
    ]
    
    for text in test_cases:
        result = predictor.predict(text, url=text if text.startswith('http') else None)
        print(f"Text: {text[:50]}...")
        print(f"Result: {result}")
        print("-" * 50)
