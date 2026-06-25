"""
Executive Investigation Report — comprehensive report generator.

Generates a structured, frontend-ready JSON report from existing pipeline data.
No pipeline logic changes — pure data aggregation from already-computed fields.
"""
import structlog
from typing import Any, Dict, List, Optional
from datetime import datetime

logger = structlog.get_logger(__name__)


def generate_executive_report(
    risk_score: int = 0,
    severity: str = "Safe",
    decision: str = "REVIEW",
    override_reason: Optional[str] = None,
    original_score: Optional[float] = None,
    banking_result: Optional[Dict[str, Any]] = None,
    banking_findings: Optional[List[Dict[str, Any]]] = None,
    compliance_findings: Optional[List[Dict[str, Any]]] = None,
    xai_findings: Optional[List[Dict[str, Any]]] = None,
    anomaly_findings: Optional[List[Dict[str, Any]]] = None,
    evidence_correlation: Optional[Dict[str, Any]] = None,
    root_cause: Optional[str] = None,
    fraud_categories: Optional[Dict[str, Any]] = None,
    decision_card: Optional[Dict[str, Any]] = None,
    investigation_summary: Optional[Dict[str, Any]] = None,
    timeline: Optional[List[Dict[str, Any]]] = None,
    risk_categories: Optional[List[Any]] = None,
    findings: Optional[List[Any]] = None,
    fraud_confidence: int = 0,
    detection_confidence: Optional[int] = None,
    fraud_risk: Optional[int] = None,
    evidence_quality: Optional[float] = None,
    recommendations: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Generate a comprehensive executive investigation report.

    Returns exportable JSON with sections:
      - executive_summary
      - technical_findings
      - evidence_summary
      - timeline_overview
      - compliance
      - recommendations
      - decision
    """
    banking_findings = banking_findings or []
    compliance_findings = compliance_findings or []
    xai_findings = xai_findings or []
    anomaly_findings = anomaly_findings or []
    recommendations = recommendations or []
    timeline = timeline or []
    risk_categories_list = list(risk_categories or [])
    findings_list = list(findings or [])

    bank_name = ""
    if banking_result:
        bank_name = banking_result.get("bank_name", "")

    # ── Executive Summary ──
    exec_summary_parts = []
    exec_summary_parts.append(f"Investigation {'completed' if decision != 'REVIEW' else 'requires review'}.")
    exec_summary_parts.append(f"Overall risk: {risk_score}/100 ({severity}).")
    if bank_name:
        exec_summary_parts.append(f"Document identified as {bank_name.title()} statement.")
    if root_cause:
        exec_summary_parts.append(f"Primary concern: {root_cause[:200]}.")
    if override_reason:
        exec_summary_parts.append(f"Override: {override_reason}.")

    # ── Technical Findings ──
    tech_findings = []

    # Module-level scores from risk_categories
    for rc in risk_categories_list:
        label = getattr(rc, 'label', None) or rc.get("label", rc.get("key", "Module"))
        score = getattr(rc, 'score', None) or rc.get("score", 0)
        tech_findings.append({
            "module": label,
            "score": round(score, 1),
            "findings_count": getattr(rc, 'findings_count', None) or rc.get("findings_count", 0),
        })

    # Individual banking findings
    for f in banking_findings:
        tech_findings.append({
            "module": "Banking Authenticity",
            "finding": f.get("finding", ""),
            "severity": f.get("severity", "LOW"),
            "risk_points": f.get("risk_points", 0),
        })

    # Compliance findings
    for f in compliance_findings:
        tech_findings.append({
            "module": "AML & Compliance",
            "finding": f.get("finding_description", ""),
            "regulation": f.get("regulation", ""),
            "severity": f.get("compliance_severity", "LOW"),
        })

    # XAI findings
    for f in xai_findings:
        tech_findings.append({
            "module": "Document Metadata & Content",
            "finding": f.get("plain_english", f.get("description", f.get("finding_type", ""))),
            "severity": f.get("severity", "LOW"),
        })

    # Anomaly findings
    for f in anomaly_findings:
        tech_findings.append({
            "module": "Behavioural Pattern Analysis",
            "finding": f.get("explanation", ""),
            "severity": f.get("severity", "LOW"),
        })

    # ── Evidence Summary ──
    evidence_summary = {
        "fraud_confidence": fraud_confidence,
        "detection_confidence": detection_confidence,
        "fraud_risk": fraud_risk,
        "evidence_quality": evidence_quality,
        "root_cause": root_cause,
        "fraud_categories": fraud_categories,
        "total_findings": len(findings_list),
    }

    # ── Timeline ──
    timeline_overview = []
    total_ms = 0
    for t in timeline:
        name = t.get("name", "Stage")
        dur = t.get("duration_ms", 0)
        status = t.get("status", "UNKNOWN")
        total_ms += dur
        timeline_overview.append({
            "stage": name,
            "duration_ms": dur,
            "status": status,
        })
    timeline_overview.append({
        "stage": "Total",
        "duration_ms": round(total_ms, 2),
        "status": "",
    })

    # ── Compliance ──
    compliance_section = []
    for f in compliance_findings:
        compliance_section.append({
            "regulation": f.get("regulation", ""),
            "finding": f.get("finding_description", ""),
            "severity": f.get("compliance_severity", "LOW"),
            "action": f.get("required_action", ""),
        })

    # ── Recommendations ──
    recs_list = list(recommendations)
    if decision_card:
        card_rec = decision_card.get("recommended_action", "")
        if card_rec and card_rec not in recs_list:
            recs_list.insert(0, card_rec)

    if not recs_list:
        if risk_score >= 75:
            recs_list.append("Immediate escalation to fraud investigation team")
        elif risk_score >= 30:
            recs_list.append("Manual review by authorised signatory")
        else:
            recs_list.append("Standard processing — no action required")

    # ── Decision ──
    decision_section = {
        "decision": decision,
        "risk_score": risk_score,
        "severity": severity,
        "original_score": original_score,
        "override_reason": override_reason,
        "fraud_type": fraud_categories.get("primary") if fraud_categories else None,
    }

    report = {
        "report_id": datetime.utcnow().strftime("RPT-%Y%m%d-%H%M%S"),
        "generated_at": datetime.utcnow().isoformat(),
        "executive_summary": " ".join(exec_summary_parts),
        "technical_findings": tech_findings,
        "evidence_summary": evidence_summary,
        "timeline_overview": timeline_overview,
        "compliance": compliance_section,
        "recommendations": recs_list,
        "decision": decision_section,
    }

    logger.info("Executive report generated", risk_score=risk_score, decision=decision)
    return report
