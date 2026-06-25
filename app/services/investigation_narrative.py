"""
Investigation Narrative Engine.

Reads every completed module and generates a deterministic
investigation story. Pure rule-based, no AI/LLM.

Output:
  executive_summary   — high-level overview
  technical_summary   — per-module technical detail
  business_summary    — business impact assessment
  recommendation_reason — why this decision was reached
"""
import structlog
from typing import Any, Dict, List, Optional

logger = structlog.get_logger(__name__)


def _describe_ocr(xai_findings: List[Dict[str, Any]], word_count: int) -> str:
    if not xai_findings:
        return ""
    ocr_issues = [f for f in xai_findings if f.get("finding_type") in ("low_confidence", "missing_field")]
    if ocr_issues:
        return f"OCR extracted only {word_count} words, which is insufficient for reliable analysis."
    if word_count > 200:
        return f"OCR completed successfully — {word_count} words extracted with high confidence."
    return f"OCR completed — {word_count} words extracted."


def _describe_metadata(xai_findings: List[Dict[str, Any]], meta: Optional[Dict[str, Any]]) -> str:
    meta_findings = [f for f in xai_findings if f.get("finding_type") in ("metadata_missing", "software_origin", "author_mismatch", "template_document")]
    if not meta_findings:
        pdf_meta = (meta or {}).get("pdf_metadata", {}) if meta else {}
        if pdf_meta and any(v for v in pdf_meta.values()):
            return "Document metadata is present and appears normal."
        return ""
    parts = []
    for f in meta_findings:
        parts.append(f.get("plain_english", f.get("description", "")))
    return "Metadata analysis: " + "; ".join(parts) + "."


def _describe_banking(banking_findings: List[Dict[str, Any]], banking_result: Optional[Dict[str, Any]]) -> str:
    if not banking_findings:
        if banking_result and banking_result.get("bank_name"):
            return f"Banking authenticity passed for {banking_result['bank_name']}."
        return "Banking authenticity analysis completed."
    parts = []
    for f in banking_findings:
        parts.append(f.get("finding", ""))
    return "Banking authenticity: " + "; ".join(parts) + "."


def _describe_financial(banking_findings: List[Dict[str, Any]], banking_result: Optional[Dict[str, Any]]) -> str:
    integrity_findings = [f for f in banking_findings if f.get("field") == "transaction_integrity"]
    if not integrity_findings:
        if banking_result and banking_result.get("transaction_count", 0) > 0:
            return "Financial reconciliation checks passed."
        return ""
    parts = []
    for f in integrity_findings:
        parts.append(f.get("finding", ""))
    return "Financial integrity: " + "; ".join(parts) + "."


def _describe_aml(compliance_findings: List[Dict[str, Any]]) -> str:
    aml_findings = [f for f in compliance_findings if "aml" in f.get("regulation", "").lower() or "pmla" in f.get("regulation", "").lower()]
    if not aml_findings:
        if compliance_findings:
            return "Compliance screening completed."
        return ""
    parts = []
    for f in aml_findings:
        parts.append(f.get("finding_description", ""))
    return "AML screening: " + "; ".join(parts) + "."


def _describe_compliance(compliance_findings: List[Dict[str, Any]]) -> str:
    non_aml = [f for f in compliance_findings if "aml" not in f.get("regulation", "").lower() and "pmla" not in f.get("regulation", "").lower()]
    if not non_aml:
        return ""
    parts = []
    for f in non_aml:
        parts.append(f"{f.get('regulation', 'regulation')}: {f.get('finding_description', '')}")
    return "Compliance review: " + "; ".join(parts) + "."


def _describe_signature(signature_intel_result: Optional[Dict[str, Any]]) -> str:
    if not signature_intel_result:
        return ""
    if signature_intel_result.get("has_signatures"):
        return f"Signature analysis found {signature_intel_result.get('image_count', 0)} signature region(s) with {signature_intel_result.get('max_confidence', 0):.0%} confidence."
    return "No signature regions detected in the document."


def _describe_fraud_patterns(fraud_patterns: List[Dict[str, Any]]) -> str:
    if not fraud_patterns:
        return ""
    parts = []
    for p in fraud_patterns:
        parts.append(p.get("description", ""))
    return "Fraud pattern detection: " + "; ".join(parts) + "."


def generate_narrative(
    xai_findings: Optional[List[Dict[str, Any]]] = None,
    banking_findings: Optional[List[Dict[str, Any]]] = None,
    banking_result: Optional[Dict[str, Any]] = None,
    compliance_findings: Optional[List[Dict[str, Any]]] = None,
    signature_intel_result: Optional[Dict[str, Any]] = None,
    fraud_patterns: Optional[List[Dict[str, Any]]] = None,
    meta: Optional[Dict[str, Any]] = None,
    word_count: int = 0,
    risk_score: int = 0,
    decision: str = "REVIEW",
    override_reason: Optional[str] = None,
) -> Dict[str, str]:
    """Generate a deterministic investigation narrative from all modules."""
    xai_findings = xai_findings or []
    banking_findings = banking_findings or []
    compliance_findings = compliance_findings or []
    fraud_patterns = fraud_patterns or []

    # ── Build per-module sentences ──
    ocr_sentence = _describe_ocr(xai_findings, word_count)
    meta_sentence = _describe_metadata(xai_findings, meta)
    banking_sentence = _describe_banking(banking_findings, banking_result)
    financial_sentence = _describe_financial(banking_findings, banking_result)
    aml_sentence = _describe_aml(compliance_findings)
    compliance_sentence = _describe_compliance(compliance_findings)
    sig_sentence = _describe_signature(signature_intel_result)
    fraud_sentence = _describe_fraud_patterns(fraud_patterns)

    # ── Executive Summary (concise story) ──
    exec_parts = []
    if ocr_sentence:
        exec_parts.append(ocr_sentence.rstrip("."))
    if meta_sentence:
        exec_parts.append(meta_sentence.rstrip("."))
    if banking_sentence:
        exec_parts.append(banking_sentence.rstrip("."))
    if financial_sentence:
        exec_parts.append(financial_sentence.rstrip("."))
    if aml_sentence:
        exec_parts.append(aml_sentence.rstrip("."))
    if compliance_sentence:
        exec_parts.append(compliance_sentence.rstrip("."))
    if sig_sentence:
        exec_parts.append(sig_sentence.rstrip("."))
    if fraud_sentence:
        exec_parts.append(fraud_sentence.rstrip("."))

    findings_count = len(banking_findings) + len(compliance_findings)
    if findings_count == 0 and risk_score < 20:
        exec_parts.append("No significant issues were detected across any module")
    elif findings_count == 0:
        exec_parts.append("Minor anomalies detected but no specific findings were raised")

    decision_text = {"APPROVE": "approval", "REVIEW": "manual review", "REJECT": "rejection", "ESCALATE": "escalation"}
    dec_label = decision_text.get(decision, "review")
    exec_parts.append(f"Based on these findings the system recommends {dec_label}")

    executive_summary = ". ".join(exec_parts) + "."

    # ── Technical Summary (per-module detail) ──
    tech_parts = []
    if ocr_sentence:
        tech_parts.append(ocr_sentence)
    if meta_sentence:
        tech_parts.append(meta_sentence)
    if banking_sentence:
        tech_parts.append(banking_sentence)
    if financial_sentence:
        tech_parts.append(financial_sentence)
    if aml_sentence:
        tech_parts.append(aml_sentence)
    if compliance_sentence:
        tech_parts.append(compliance_sentence)
    if sig_sentence:
        tech_parts.append(sig_sentence)
    if fraud_sentence:
        tech_parts.append(fraud_sentence)
    technical_summary = " ".join(tech_parts) if tech_parts else "All analysis modules completed without findings."

    # ── Business Summary ──
    biz_parts = []
    if risk_score >= 75:
        biz_parts.append("High risk of financial fraud")
    elif risk_score >= 50:
        biz_parts.append("Moderate risk detected")
    elif risk_score >= 25:
        biz_parts.append("Low-to-moderate risk")
    else:
        biz_parts.append("Low risk — document appears legitimate")

    bank_name = (banking_result or {}).get("bank_name")
    if bank_name:
        biz_parts.append(f"Document claims to be from {bank_name}")

    issue_count = len(banking_findings) + len(compliance_findings)
    if issue_count > 0:
        biz_parts.append(f"{issue_count} issue(s) requiring attention")
    else:
        biz_parts.append("No issues requiring attention")

    business_summary = ". ".join(biz_parts) + "."

    # ── Recommendation Reason ──
    reason_parts = []
    if override_reason:
        reason_parts.append(override_reason)
    else:
        if banking_findings:
            top = banking_findings[0].get("finding", "")
            if top:
                reason_parts.append(top)
        if risk_score >= 75:
            reason_parts.append("critical risk threshold exceeded")
        elif risk_score >= 50:
            reason_parts.append("multiple risk indicators present")
        elif risk_score >= 25:
            reason_parts.append("minor findings require verification")
        else:
            reason_parts.append("all checks passed")

    recommendation_reason = " — ".join(reason_parts) if reason_parts else "Standard review process recommended."

    logger.info(
        "Investigation narrative generated",
        exec_len=len(executive_summary),
        tech_len=len(technical_summary),
        biz_len=len(business_summary),
    )

    return {
        "executive_summary": executive_summary[:600],
        "technical_summary": technical_summary[:800],
        "business_summary": business_summary[:500],
        "recommendation_reason": recommendation_reason[:400],
    }
