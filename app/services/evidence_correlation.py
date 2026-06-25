"""
Evidence Correlation Engine.

Correlates findings from all pipeline stages (banking authenticity,
financial integrity, metadata, OCR, compliance, anomaly detection,
signature intelligence) into one unified investigation.

Output:
  - root_cause: primary explanation
  - fraud_chain: ordered sequence of anomalies
  - confidence: overall confidence (0-100)
  - primary_reason: one-line summary
"""
import structlog
from typing import Any, Dict, List, Optional

logger = structlog.get_logger(__name__)


def correlate_evidence(
    xai_findings: Optional[List[Dict[str, Any]]] = None,
    anomaly_findings: Optional[List[Dict[str, Any]]] = None,
    compliance_findings: Optional[List[Dict[str, Any]]] = None,
    banking_findings: Optional[List[Dict[str, Any]]] = None,
    signature_findings: Optional[List[Dict[str, Any]]] = None,
    fraud_patterns: Optional[List[Dict[str, Any]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Correlate all available findings into a single evidence summary."""
    xai_findings = xai_findings or []
    anomaly_findings = anomaly_findings or []
    compliance_findings = compliance_findings or []
    banking_findings = banking_findings or []
    signature_findings = signature_findings or []
    fraud_patterns = fraud_patterns or []

    fraud_chain: List[str] = []
    root_cause_parts: List[str] = []
    reasons: List[str] = []

    if xai_findings:
        for f in xai_findings:
            desc = f.get("plain_english") or f.get("finding_type", "")
            if desc:
                fraud_chain.append(f"XAI: {desc}")
                reasons.append(desc)

    if anomaly_findings:
        for f in anomaly_findings:
            expl = f.get("explanation", "")
            if expl:
                fraud_chain.append(f"Anomaly: {expl}")
                reasons.append(expl)

    if compliance_findings:
        for f in compliance_findings:
            desc = f.get("finding_description", "")
            if desc:
                fraud_chain.append(f"Compliance: {desc}")
                reasons.append(desc)

    if banking_findings:
        for f in banking_findings:
            finding_text = f.get("finding", "")
            evidence = f.get("evidence", "")
            if finding_text:
                fraud_chain.append(f"Banking: {finding_text}")
                root_cause_parts.append(finding_text)
                reasons.append(finding_text)
            if evidence:
                reasons.append(evidence)

    if signature_findings:
        for f in signature_findings:
            finding_text = f if isinstance(f, str) else f.get("finding", str(f))
            fraud_chain.append(f"Signature: {finding_text}")
            reasons.append(str(finding_text))

    if fraud_patterns:
        for p in fraud_patterns:
            desc = p.get("description", "")
            if desc:
                fraud_chain.append(f"Fraud Pattern: {desc}")
                reasons.append(desc)

    primary_reason = root_cause_parts[0] if root_cause_parts else (
        reasons[0] if reasons else "No significant findings detected"
    )

    root_cause = "; ".join(root_cause_parts[:3]) if root_cause_parts else (
        "; ".join(reasons[:3]) if reasons else "No findings to correlate"
    )

    # Confidence: derived from weighted assessment of finding severities
    severity_scores = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 2}
    total_weight = 0
    for f in banking_findings:
        sev = f.get("severity", "LOW").upper()
        total_weight += severity_scores.get(sev, 2)
    for f in compliance_findings:
        sev = f.get("compliance_severity", "LOW").upper()
        total_weight += severity_scores.get(sev, 2)
    for f in anomaly_findings:
        sev = f.get("severity", "LOW").upper()
        total_weight += severity_scores.get(sev, 2)
    n_findings = len(banking_findings) + len(compliance_findings) + len(anomaly_findings) + len(xai_findings)
    if n_findings > 0:
        confidence = min(round(total_weight * 100 / (n_findings * 30 + 1)), 99)
    else:
        confidence = 0
    confidence = max(confidence, 5)

    logger.info(
        "Evidence correlation complete",
        root_cause=root_cause[:100],
        fraud_chain_length=len(fraud_chain),
        confidence=confidence,
    )

    return {
        "root_cause": root_cause[:500],
        "fraud_chain": fraud_chain[:10],
        "confidence": confidence,
        "primary_reason": primary_reason[:300],
    }


def build_evidence_chain(
    xai_findings: Optional[List[Dict[str, Any]]] = None,
    anomaly_findings: Optional[List[Dict[str, Any]]] = None,
    compliance_findings: Optional[List[Dict[str, Any]]] = None,
    banking_findings: Optional[List[Dict[str, Any]]] = None,
    signature_findings: Optional[List[Dict[str, Any]]] = None,
    fraud_patterns: Optional[List[Dict[str, Any]]] = None,
    ocr_insufficient: bool = False,
) -> Dict[str, Any]:
    """
    Build a cause-effect evidence chain from all pipeline findings.

    Returns:
      fraud_chain: list of {cause, effect} pairs forming a logical chain
      root_cause:  the originating trigger
      confidence:   overall confidence (0-100)
    """
    banking_findings = banking_findings or []
    compliance_findings = compliance_findings or []
    xai_findings = xai_findings or []
    anomaly_findings = anomaly_findings or []
    signature_findings = signature_findings or []
    fraud_patterns = fraud_patterns or []

    chain: List[Dict[str, str]] = []
    root_cause_parts: List[str] = []
    all_finding_texts: List[str] = []

    # ── OCR / text issues ──
    if ocr_insufficient:
        chain.append({
            "cause": "Insufficient OCR text extraction",
            "effect": "Unable to perform full document analysis",
        })
        root_cause_parts.append("Insufficient OCR text extraction")
        all_finding_texts.append("Insufficient OCR text extraction")

    # ── XAI (metadata / OCR / template) ──
    for f in xai_findings:
        text = f.get("plain_english", "") or f.get("description", "")
        ft = f.get("finding_type", "")
        if text:
            cause = text
            effect = "Document authenticity confidence reduced"
            if ft == "template_document":
                effect = "Document classified as template-based"
            elif ft == "software_origin":
                effect = "Document origin appears non-standard"
            elif ft == "metadata_missing":
                effect = "Unable to verify document provenance"
            chain.append({"cause": cause, "effect": effect})
            root_cause_parts.append(text)
            all_finding_texts.append(text)

    # ── Fraud patterns ──
    for p in fraud_patterns:
        desc = p.get("description", "")
        if desc:
            cause = desc
            effect = "Transaction pattern flagged as suspicious"
            if "round" in desc.lower():
                effect = "Transactions appear artificially structured"
            elif "repeated" in desc.lower():
                effect = "Possible fabricated transaction entries"
            elif "night" in desc.lower() or "late-night" in desc.lower():
                effect = "Unusual banking activity pattern detected"
            chain.append({"cause": cause, "effect": effect})
            root_cause_parts.append(desc)
            all_finding_texts.append(desc)

    # ── Banking authenticity ──
    for f in banking_findings:
        finding_text = f.get("finding", "")
        field = f.get("field", "")
        if not finding_text:
            continue
        cause = finding_text
        effect = "Banking authenticity confidence reduced"
        if field == "bank_identity":
            effect = "Unable to verify issuing institution"
        elif field == "document_authenticity":
            effect = "Document may be fabricated from a template"
        elif field == "currency_consistency":
            effect = "Currency inconsistency raises fraud suspicion"
        elif field == "transaction_integrity":
            effect = "Financial arithmetic failure detected"
        chain.append({"cause": cause, "effect": effect})
        root_cause_parts.append(finding_text)
        all_finding_texts.append(finding_text)

    # ── Anomaly detection ──
    for f in anomaly_findings:
        expl = f.get("explanation", "")
        if expl:
            chain.append({
                "cause": expl,
                "effect": "Statistical anomaly detected in document features",
            })
            all_finding_texts.append(expl)

    # ── Compliance ──
    for f in compliance_findings:
        desc = f.get("finding_description", "")
        reg = f.get("regulation", "")
        if desc:
            effect = f"Compliance risk under {reg}" if reg else "Compliance risk flagged"
            chain.append({"cause": desc, "effect": effect})
            all_finding_texts.append(desc)

    # ── Signature ──
    for f in signature_findings:
        text = f if isinstance(f, str) else f.get("finding", str(f))
        if text:
            chain.append({
                "cause": str(text),
                "effect": "Signature verification required",
            })
            all_finding_texts.append(str(text))

    # ── Chaining: link adjacent pairs ──
    chained: List[Dict[str, str]] = []
    for i in range(len(chain)):
        entry = dict(chain[i])
        if i > 0:
            entry["cause"] = chain[i - 1]["effect"]
        if i + 1 < len(chain):
            pass
        else:
            entry["effect"] = "Manual Review" if risk_score_from_findings(banking_findings, compliance_findings) >= 25 else "Approved"
        chained.append(entry)

    if not chained:
        chained = [{"cause": "No issues detected", "effect": "Approved"}]

    # ── Root cause ──
    root_cause = root_cause_parts[0] if root_cause_parts else "No primary cause identified"

    # ── Confidence ──
    severity_scores = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 2}
    total_weight = 0
    for f in banking_findings:
        total_weight += severity_scores.get(f.get("severity", "LOW").upper(), 2)
    for f in compliance_findings:
        total_weight += severity_scores.get(f.get("compliance_severity", "LOW").upper(), 2)
    for f in anomaly_findings:
        total_weight += severity_scores.get(f.get("severity", "LOW").upper(), 2)
    n = max(len(banking_findings) + len(compliance_findings) + len(anomaly_findings), 1)
    confidence = min(round(total_weight * 100 / (n * 30 + 1)), 99)
    confidence = max(confidence, 5)

    logger.info(
        "Evidence chain built",
        chain_length=len(chained),
        root_cause=root_cause[:80],
        confidence=confidence,
    )

    return {
        "fraud_chain": chained[:10],
        "root_cause": root_cause[:300],
        "confidence": confidence,
    }


def risk_score_from_findings(
    banking_findings: List[Dict[str, Any]],
    compliance_findings: List[Dict[str, Any]],
) -> int:
    """Quick heuristic risk score from findings (no aggregator dependency)."""
    score = 0
    for f in banking_findings:
        score += f.get("risk_points", 0)
    for f in compliance_findings:
        sev = f.get("compliance_severity", "LOW").upper()
        score += {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 2}.get(sev, 2)
    return min(score, 100)
