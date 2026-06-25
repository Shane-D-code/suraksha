"""
Decision Card Generator.

Produces a concise decision summary card with:
  - decision (APPROVE / REVIEW / ESCALATE / REJECT)
  - risk (LOW / MEDIUM / HIGH / CRITICAL)
  - confidence (0-100)
  - primary_reason
  - review_team (suggested team for manual review)

Does NOT replace existing recommendations.
"""
import structlog
from typing import Any, Dict, List, Optional

logger = structlog.get_logger(__name__)

REVIEW_TEAM_MAP = {
    "Template Fraud": "Document Verification Team",
    "Metadata Manipulation": "Forensic Document Analysis Team",
    "Financial Manipulation": "Financial Crimes Investigation Unit",
    "Identity Fraud": "Identity Verification Team",
    "Signature Fraud": "Signature Verification Team",
    "Currency Fraud": "Foreign Exchange Compliance Team",
    "Institution Mismatch": "Institution Verification Team",
    "Compliance Risk": "Regulatory Compliance Team",
    "Unclassified": "Loan Verification Team",
}

DEFAULT_TEAM = "Loan Verification Team"


def generate_decision_card(
    risk_score: int = 0,
    fraud_confidence: int = 0,
    fraud_categories: Optional[Dict[str, Any]] = None,
    root_cause: Optional[str] = None,
    existing_decision: Optional[str] = None,
    banking_findings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Generate a decision card summary."""
    banking_findings = banking_findings or []
    fraud_categories = fraud_categories or {}

    primary_category = fraud_categories.get("primary", "Unclassified")
    review_team = REVIEW_TEAM_MAP.get(primary_category, DEFAULT_TEAM)

    if existing_decision:
        decision = existing_decision
    elif risk_score >= 75:
        decision = "REJECT"
    elif risk_score >= 50:
        decision = "ESCALATE"
    elif risk_score >= 25:
        decision = "REVIEW"
    else:
        decision = "APPROVE"

    if risk_score >= 75:
        risk = "CRITICAL"
    elif risk_score >= 50:
        risk = "HIGH"
    elif risk_score >= 25:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    primary_reason = root_cause or "No significant findings"
    if not root_cause:
        finding_texts = [f.get("finding", "") for f in banking_findings
                         if f.get("risk_points", 0) > 0]
        if finding_texts:
            primary_reason = finding_texts[0]

    logger.info(
        "Decision card generated",
        decision=decision,
        risk=risk,
        confidence=fraud_confidence,
        review_team=review_team,
    )

    return {
        "decision": decision,
        "risk": risk,
        "confidence": fraud_confidence,
        "primary_reason": primary_reason[:300],
        "review_team": review_team,
    }
