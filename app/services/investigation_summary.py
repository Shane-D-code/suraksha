"""
Investigation Summary Generator.

Produces a comprehensive investigation report with:
  - Executive Summary
  - Technical Summary
  - Evidence Summary
  - Business Impact
  - Recommended Action

Pure deterministic logic, no AI/LLM.
"""
import structlog
from typing import Any, Dict, List, Optional

logger = structlog.get_logger(__name__)


def generate_investigation_summary(
    banking_findings: Optional[List[Dict[str, Any]]] = None,
    compliance_findings: Optional[List[Dict[str, Any]]] = None,
    anomaly_findings: Optional[List[Dict[str, Any]]] = None,
    xai_findings: Optional[List[Dict[str, Any]]] = None,
    fraud_patterns: Optional[List[Dict[str, Any]]] = None,
    risk_score: int = 0,
    fraud_confidence: int = 0,
    root_cause: Optional[str] = None,
    fraud_categories: Optional[Dict[str, Any]] = None,
    decision_card: Optional[Dict[str, Any]] = None,
    banking_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Generate a deterministic investigation summary."""
    banking_findings = banking_findings or []
    compliance_findings = compliance_findings or []
    anomaly_findings = anomaly_findings or []
    xai_findings = xai_findings or []
    fraud_patterns = fraud_patterns or []
    banking_result = banking_result or {}

    finding_counts = {
        "banking": len(banking_findings),
        "compliance": len(compliance_findings),
        "anomaly": len(anomaly_findings),
        "xai": len(xai_findings),
        "fraud_patterns": len(fraud_patterns),
    }
    total_findings = sum(finding_counts.values())

    # Executive Summary
    risk_label = "HIGH" if risk_score >= 50 else "MODERATE" if risk_score >= 25 else "LOW"
    exec_parts = [f"Investigation complete with overall risk assessment of {risk_label} (score: {risk_score}/100)."]
    if root_cause:
        exec_parts.append(f"Root cause: {root_cause}")
    if total_findings > 0:
        exec_parts.append(f"Analysis identified {total_findings} finding(s) across {sum(1 for v in finding_counts.values() if v > 0)} pipeline(s).")
    executive_summary = " ".join(exec_parts)

    # Technical Summary
    tech_lines = []
    for f in banking_findings:
        tech_lines.append(f"[Banking] {f.get('finding', '')} (severity: {f.get('severity', 'N/A')})")
    for f in compliance_findings:
        tech_lines.append(f"[Compliance] {f.get('finding_description', '')} (regulation: {f.get('regulation', 'N/A')})")
    for f in anomaly_findings:
        tech_lines.append(f"[Anomaly] {f.get('explanation', '')} (method: {f.get('method', 'N/A')})")
    for f in xai_findings:
        tech_lines.append(f"[XAI] {f.get('plain_english', '')}")
    for p in fraud_patterns:
        tech_lines.append(f"[Fraud Pattern] {p.get('description', '')}")
    technical_summary = "\n".join(tech_lines[:10]) if tech_lines else "No technical findings to report."

    # Evidence Summary
    evidence_items = []
    for f in banking_findings:
        ev = f.get("evidence", "")
        if ev:
            evidence_items.append(f"- {f.get('finding', '')}: {ev}")
    evidence_summary = "\n".join(evidence_items[:5]) if evidence_items else "No supporting evidence collected."

    # Business Impact
    impact_parts = []
    if risk_score >= 75:
        impact_parts.append("High risk of financial fraud — immediate escalation recommended.")
    elif risk_score >= 50:
        impact_parts.append("Moderate risk detected — may indicate attempted fraud or documentation errors.")
    else:
        impact_parts.append("Low risk — standard processing can proceed.")
    
    bank_name = banking_result.get("bank_name", "")
    if bank_name:
        impact_parts.append(f"Document claims to be from {bank_name}.")
    if fraud_categories:
        pc = fraud_categories.get("primary", "")
        if pc:
            impact_parts.append(f"Primary fraud category: {pc}.")
    
    business_impact = " ".join(impact_parts)

    # Recommended Action
    action = ""
    if decision_card:
        action = f"Decision: {decision_card.get('decision', 'REVIEW')}. "
        team = decision_card.get("review_team", "Loan Verification Team")
        action += f"Assign to {team} for processing."
    elif risk_score >= 75:
        action = "Escalate to fraud operations team for immediate investigation."
    elif risk_score >= 50:
        action = "Flag for review by financial crimes investigation unit."
    elif risk_score >= 25:
        action = "Route to standard review queue for manual verification."
    else:
        action = "Approve — document appears authentic and low-risk."

    logger.info("Investigation summary generated", total_findings=total_findings)

    return {
        "executive_summary": executive_summary[:500],
        "technical_summary": technical_summary[:1000],
        "evidence_summary": evidence_summary[:500],
        "business_impact": business_impact[:500],
        "recommended_action": action[:500],
    }
