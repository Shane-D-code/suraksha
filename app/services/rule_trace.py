"""
Rule Trace & Risk Waterfall generators.

Append-only rule trace and cumulative risk waterfall.
These are pure visualization metadata — do NOT alter any scoring logic.
"""
import structlog
from typing import List, Dict, Any, Optional

logger = structlog.get_logger(__name__)

# ── Rule ID and impact mappings ──────────────────────────────────────

BANKING_RULE_IDS = {
    "bank_identity": "BANK-IDENTITY",
    "document_authenticity": "BANK-DOC_AUTH",
    "currency_consistency": "BANK-CURRENCY",
    "transaction_integrity": "BANK-FIN_INTEGRITY",
}

COMPLIANCE_REGULATION_IDS = {
    "RBI KYC Guidelines": "RBI-KYC",
    "Anti-Money Laundering (PMLA 2002)": "AML-PMLA",
    "Digital Personal Data Protection Act 2023": "DPDP-ACT",
    "CERT-In Directions": "CERT-IN",
}

SEVERITY_IMPACT = {"LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 50}

EFFECT_MAP: Dict[str, str] = {
    "CRITICAL": "Rejected",
    "HIGH": "Escalation",
    "MEDIUM": "Manual Review",
    "LOW": "Flagged",
}

FINAL_WEIGHTS = {
    "banking_authenticity": 0.20,
    "financial_integrity": 0.15,
    "compliance": 0.30,
    "anomaly": 0.15,
    "xai": 0.10,
    "signature": 0.05,
    "ocr_reliability": 0.05,
}


def _final_effect(severity: str) -> str:
    return EFFECT_MAP.get(severity.upper(), "Flagged")


def build_rule_trace(
    banking_findings: Optional[List[Dict[str, Any]]] = None,
    compliance_findings: Optional[List[Dict[str, Any]]] = None,
    xai_findings: Optional[List[Dict[str, Any]]] = None,
    anomaly_findings: Optional[List[Dict[str, Any]]] = None,
    signature_findings: Optional[List[Any]] = None,
    fraud_patterns: Optional[List[Dict[str, Any]]] = None,
    risk_score: int = 0,
) -> List[Dict[str, str]]:
    """
    Build an append-only rule trace from all pipeline findings.

    Each entry: {rule_id, module, reason, impact, final_effect}.
    """
    trace: List[Dict[str, str]] = []

    # ── Banking Authenticity ──
    for f in banking_findings or []:
        field = f.get("field", "")
        rule_id = BANKING_RULE_IDS.get(field, f"BANK-{field[:20].upper()}")
        reason = f.get("finding", "Unknown finding")
        risk_pts = f.get("risk_points", 0)
        impact = f"Authenticity -{risk_pts}" if risk_pts else f.get("severity", "LOW")
        severity = f.get("severity", "LOW")
        trace.append({
            "rule_id": rule_id,
            "module": "Banking Authenticity",
            "reason": reason[:200],
            "impact": impact,
            "final_effect": _final_effect(severity),
        })

    # ── AML & Compliance ──
    for f in compliance_findings or []:
        reg = f.get("regulation", "")
        rule_id = COMPLIANCE_REGULATION_IDS.get(reg, f"COMP-{reg[:20]}")
        reason = f.get("finding_description", "Compliance finding")
        sev = f.get("compliance_severity", "LOW")
        pts = SEVERITY_IMPACT.get(sev, 5)
        impact = f"Compliance -{pts}"
        trace.append({
            "rule_id": rule_id,
            "module": "AML & Compliance",
            "reason": reason[:200],
            "impact": impact,
            "final_effect": _final_effect(sev),
        })

    # ── Document Metadata & Content (XAI) ──
    for f in xai_findings or []:
        ft = f.get("finding_type", "unknown")
        rule_id = f"XAI-{ft[:20].upper()}"
        reason = f.get("plain_english", f.get("description", ft))
        sev = f.get("severity", "LOW")
        pts = SEVERITY_IMPACT.get(sev, 5)
        impact = f"Metadata -{pts}"
        trace.append({
            "rule_id": rule_id,
            "module": "Document Metadata & Content",
            "reason": reason[:200],
            "impact": impact,
            "final_effect": _final_effect(sev),
        })

    # ── Behavioural Pattern Analysis (Anomaly) ──
    for f in anomaly_findings or []:
        method = f.get("method", "unknown")
        rule_id = f"ANOMALY-{method[:20].upper()}"
        reason = f.get("explanation", f.get("finding", "Anomaly detected"))
        sev = f.get("severity", "LOW")
        pts = SEVERITY_IMPACT.get(sev, 5)
        impact = f"Anomaly -{pts}"
        trace.append({
            "rule_id": rule_id,
            "module": "Behavioural Pattern Analysis",
            "reason": reason[:200],
            "impact": impact,
            "final_effect": _final_effect(sev),
        })

    # ── Signature Intelligence ──
    for f in signature_findings or []:
        text = f if isinstance(f, str) else f.get("finding", str(f))
        trace.append({
            "rule_id": "SIG-INTEL",
            "module": "Signature Intelligence",
            "reason": str(text)[:200],
            "impact": "Signature -5",
            "final_effect": "Flagged",
        })

    # ── Fraud Pattern Detection ──
    for p in fraud_patterns or []:
        pat = p.get("pattern", "unknown")
        rule_id = f"PATTERN-{pat[:20].upper()}"
        desc = p.get("description", "Suspicious pattern")
        trace.append({
            "rule_id": rule_id,
            "module": "Fraud Pattern Detection",
            "reason": desc[:200],
            "impact": "Pattern -15",
            "final_effect": "Manual Review",
        })

    logger.info("Rule trace built", count=len(trace))
    return trace


def build_risk_waterfall(
    risk_categories: Optional[List[Dict[str, Any]]] = None,
    decision_path: Optional[List[Dict[str, Any]]] = None,
    risk_score: int = 0,
    original_score: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """
    Build a cumulative risk waterfall — pure visualization metadata.

    Shows how risk accumulates stage by stage.
    Does NOT alter any scoring calculation.
    """
    waterfall: List[Dict[str, Any]] = []

    base_risk = 5
    cumulative = base_risk

    # Stage 1: Base Risk
    waterfall.append({"stage": "Base Risk", "score": base_risk})

    # Stage 2: Per-module contributions (from risk_categories)
    rc_list = list(risk_categories or [])
    if rc_list:
        for rc in rc_list:
            label = rc.get("label", rc.get("key", "Module"))
            score_val = rc.get("score", 0)
            weight = FINAL_WEIGHTS.get(rc.get("key", ""), 0)
            delta = round(score_val * weight)
            if delta > 0:
                cumulative += delta
                waterfall.append({
                    "stage": label,
                    "delta": delta,
                    "total": cumulative,
                })

    # Stage 3: Balancing adjustment to match final risk_score
    if cumulative != risk_score:
        delta = risk_score - cumulative
        label = "Override" if original_score is not None and original_score != risk_score else "Adjustments"
        cumulative = risk_score
        waterfall.append({
            "stage": label,
            "delta": delta,
            "total": cumulative,
        })

    logger.info("Risk waterfall built", stages=len(waterfall), final_score=risk_score)
    return waterfall
