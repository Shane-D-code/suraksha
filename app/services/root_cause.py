"""
Root Cause Generator.

Produces a single concise investigation summary explaining the
primary reason for the risk assessment. Pure rule-based, no LLM.
"""
import structlog
from typing import Any, Dict, List, Optional

logger = structlog.get_logger(__name__)


def generate_root_cause(
    banking_findings: Optional[List[Dict[str, Any]]] = None,
    compliance_findings: Optional[List[Dict[str, Any]]] = None,
    anomaly_findings: Optional[List[Dict[str, Any]]] = None,
    xai_findings: Optional[List[Dict[str, Any]]] = None,
    fraud_patterns: Optional[List[Dict[str, Any]]] = None,
    risk_score: int = 0,
) -> str:
    """Generate a rule-based root cause summary."""
    banking_findings = banking_findings or []
    compliance_findings = compliance_findings or []
    anomaly_findings = anomaly_findings or []
    xai_findings = xai_findings or []
    fraud_patterns = fraud_patterns or []

    reasons: List[str] = []

    # Check for template/sample indicators
    template_findings = [f for f in banking_findings
                         if f.get("field") == "document_authenticity"
                         and f.get("risk_points", 0) >= 40]
    if template_findings:
        reasons.append("document appears to be from a public template source")

    # Check for missing banking fields
    missing_ifsc = any("ifsc" in f.get("finding", "").lower()
                       and "missing" in f.get("finding", "").lower()
                       for f in banking_findings)
    missing_account = any("account number" in f.get("finding", "").lower()
                          and "missing" in f.get("finding", "").lower()
                          for f in banking_findings)
    if missing_ifsc and missing_account:
        reasons.append("mandatory IFSC code and account number are both missing")
    elif missing_ifsc:
        reasons.append("mandatory IFSC information is missing while other banking identifiers are present")
    elif missing_account:
        reasons.append("account number is missing from the document")

    # Check for identity mismatch
    bank_conflict = any("bank identity conflict" in f.get("finding", "").lower()
                        for f in banking_findings)
    if bank_conflict:
        reasons.append("bank identity information is internally inconsistent")

    # Check for currency mismatch
    currency_issue = any(f.get("field") == "currency_consistency"
                         for f in banking_findings)
    if currency_issue:
        reasons.append("currency detected in the document does not match expected INR")

    # Check financial integrity
    balance_issue = any("reconciliation failure" in f.get("finding", "").lower()
                        for f in banking_findings)
    txn_mismatch = any("transaction total mismatch" in f.get("finding", "").lower()
                       for f in banking_findings)
    if balance_issue and txn_mismatch:
        reasons.append("financial integrity checks failed due to balance reconciliation and transaction total mismatches")
    elif balance_issue:
        reasons.append("balance reconciliation check failed")
    elif txn_mismatch:
        reasons.append("transaction totals do not match individual entries")

    # Check compliance findings
    high_compliance = [f for f in compliance_findings
                       if f.get("compliance_severity", "").upper() in ("HIGH", "CRITICAL")]
    if high_compliance:
        reasons.append(f"{len(high_compliance)} high-severity compliance findings were identified")

    # Check fraud patterns
    for p in fraud_patterns:
        pattern = p.get("pattern", "")
        if pattern == "round_amounts":
            reasons.append("amounts are suspiciously rounded to thousands, suggesting fabricated data")
        elif pattern == "repeated_transactions":
            reasons.append("multiple identical transaction amounts suggest fabricated entries")
        elif pattern == "unusual_times":
            reasons.append("transactions occurred during unusual late-night hours")

    # Check anomaly detection
    high_anomalies = [f for f in anomaly_findings
                      if f.get("severity", "").upper() in ("HIGH", "CRITICAL")]
    if high_anomalies:
        reasons.append("statistical anomalies were detected in document features")

    # Check XAI
    for f in xai_findings:
        if f.get("severity", "").upper() in ("HIGH", "CRITICAL"):
            reasons.append(f.get("plain_english", "").lower())

    # Fraud patterns as general indicators
    if fraud_patterns and not reasons:
        reasons.append("suspicious transaction patterns were detected")

    if not reasons:
        if risk_score < 20:
            return "The uploaded document passed all validation checks and no significant issues were detected."
        return "The document exhibits minor anomalies that warrant further review."

    combined = "; ".join(reasons[:4])
    summary = (
        f"The uploaded document is flagged because {combined}, "
        f"preventing complete verification of its authenticity."
    )
    logger.info("Root cause generated", summary=summary[:200])
    return summary[:600]
