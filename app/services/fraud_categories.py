"""
Fraud Category Classifier.

Categorises detected fraud into predefined categories:
  - Template Fraud
  - Metadata Manipulation
  - Financial Manipulation
  - Identity Fraud
  - Signature Fraud
  - Currency Fraud
  - Institution Mismatch
  - Compliance Risk

Returns primary and secondary category assignments.
"""
import structlog
from typing import Any, Dict, List, Optional

logger = structlog.get_logger(__name__)


CATEGORY_DEFINITIONS = {
    "Template Fraud": {
        "keywords": ["template.net", "sample", "specimen", "demo", "template"],
        "fields": ["document_authenticity"],
    },
    "Metadata Manipulation": {
        "keywords": ["photoshop", "canva", "pdfedit", "modified after creation"],
        "fields": ["metadata", "pdf_metadata"],
    },
    "Financial Manipulation": {
        "keywords": ["balance reconciliation", "transaction total mismatch",
                      "running balance", "round amount", "fabricated data"],
        "fields": ["transaction_integrity", "financial_integrity"],
    },
    "Identity Fraud": {
        "keywords": ["bank identity conflict", "missing ifsc", "missing account number",
                      "author mismatch", "identity"],
        "fields": ["bank_identity"],
    },
    "Signature Fraud": {
        "keywords": ["signature", "forgery", "signature mismatch"],
        "fields": ["signature_intelligence", "signature"],
    },
    "Currency Fraud": {
        "keywords": ["currency mismatch", "currency_consistency", "non-inr"],
        "fields": ["currency_consistency"],
    },
    "Institution Mismatch": {
        "keywords": ["bank identity", "institution mismatch"],
        "fields": ["bank_identity"],
    },
    "Compliance Risk": {
        "keywords": ["kyc", "aml", "pmla", "rbi", "cert-in", "dpdp", "compliance"],
        "fields": ["compliance"],
    },
}


def classify_fraud(
    banking_findings: Optional[List[Dict[str, Any]]] = None,
    compliance_findings: Optional[List[Dict[str, Any]]] = None,
    xai_findings: Optional[List[Dict[str, Any]]] = None,
    signature_findings: Optional[List[Dict[str, Any]]] = None,
    fraud_patterns: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Classify detected fraud into primary and secondary categories."""
    banking_findings = banking_findings or []
    compliance_findings = compliance_findings or []
    xai_findings = xai_findings or []
    signature_findings = signature_findings or []
    fraud_patterns = fraud_patterns or []

    match_scores: Dict[str, int] = {}
    all_text = ""

    for f in banking_findings:
        text = f"{f.get('finding', '')} {f.get('evidence', '')} {f.get('field', '')}"
        all_text += " " + text.lower()

    for f in compliance_findings:
        text = f"{f.get('finding_description', '')} {f.get('regulation', '')}"
        all_text += " " + text.lower()

    for f in xai_findings:
        text = f.get("plain_english", f.get("finding_type", ""))
        all_text += " " + text.lower()

    for p in fraud_patterns:
        text = f"{p.get('description', '')} {p.get('pattern', '')}"
        all_text += " " + text.lower()

    for f in signature_findings:
        text = str(f) if isinstance(f, str) else str(f.get("finding", ""))
        all_text += " " + text.lower()

    for cat, definition in CATEGORY_DEFINITIONS.items():
        score = 0
        for kw in definition["keywords"]:
            if kw.lower() in all_text:
                score += 1
        for field in definition["fields"]:
            if field.lower() in all_text:
                score += 2
        if score > 0:
            match_scores[cat] = score

    if not match_scores:
        return {"primary": "Unclassified", "secondary": []}

    sorted_cats = sorted(match_scores.items(), key=lambda x: x[1], reverse=True)
    primary = sorted_cats[0][0]
    secondary = [cat for cat, _ in sorted_cats[1:]]

    logger.info("Fraud categories classified", primary=primary, secondary=secondary)
    return {"primary": primary, "secondary": secondary[:5]}
