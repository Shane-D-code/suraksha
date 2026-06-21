"""
Document Analysis Engine.

Analyzes extracted OCR text for compliance-relevant patterns
including KYC status, document metadata, and risk indicators.
"""
import re
from typing import List, Dict, Optional


KYC_STATUS_PENDING_RE = re.compile(r"KYC\s*STATUS\s*:\s*PENDING", re.IGNORECASE)


def analyze_kyc_status(text: str) -> Optional[Dict]:
    """Analyze OCR text for pending KYC status.

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
        }

    return None


def analyze_document_text(text: str) -> List[Dict]:
    """Run all document-level text analyses and return findings."""
    findings: List[Dict] = []

    kyc = analyze_kyc_status(text)
    if kyc:
        findings.append(kyc)

    return findings
