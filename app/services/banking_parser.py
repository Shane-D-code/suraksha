"""
Banking Document Parser.

Extracts structured fields from banking document OCR text,
including KYC status, account details, and transaction metadata.
"""
import re
from typing import List, Dict, Optional


KYC_STATUS_PENDING_RE = re.compile(r"KYC\s*STATUS\s*:\s*PENDING", re.IGNORECASE)


def detect_kyc_status(text: str) -> Optional[Dict]:
    """Check OCR text for pending KYC status.

    Returns a finding dict if KYC Status: Pending is detected,
    otherwise None.
    """
    if not text:
        return None

    if KYC_STATUS_PENDING_RE.search(text):
        return {
            "severity": "HIGH",
            "risk_points": 40,
            "finding": "KYC verification incomplete",
            "field": "kyc_status",
        }

    return None


def extract_kyc_status(text: str) -> Optional[str]:
    """Extract raw KYC status value from OCR text."""
    m = re.search(r"KYC\s*STATUS\s*:\s*(\w+)", text, re.IGNORECASE)
    if m:
        return m.group(1).upper()
    return None
