"""
Final risk aggregation engine — Banking Document Authenticity Edition.

Combines outputs from the banking authenticity pipeline with traditional
signature, compliance, and anomaly modules into a single 0–100 risk score.

Priority weighting:
  Banking Authenticity (template, identity, currency)    50%
  Anomaly Detection                                      20%
  Document Metadata & Content                            10%
  Signature Verification (existing + image-based)         10%
  OCR Reliability                                        10%

The authenticity_score field (0–100) shows how trustworthy the
document appears: 100 = fully authentic, 0 = completely fabricated.
"""
import structlog
from typing import List, Tuple, Optional as TOptional
from app.models.aggregator import AggregationInput, AggregationResponse, AggregatedFinding, RiskCategory, EvidenceItem
from app.services.case_reasoning import build_case_features, get_case_store

logger = structlog.get_logger(__name__)

# --- Module weights (must sum to 1.0) ---
FINAL_WEIGHTS = {
    "banking_authenticity": 0.25,
    "financial_integrity": 0.25,
    "compliance": 0.15,
    "anomaly": 0.10,
    "xai": 0.10,
    "signature": 0.05,
    "ocr_reliability": 0.10,
}

SEVERITY_MAP = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

# Base score added per finding based on severity
SEVERITY_WEIGHTS = {
    "LOW": 5,
    "MEDIUM": 15,
    "HIGH": 30,
    "CRITICAL": 50,
}

# Minimum risk_score when a specific finding is present (overrides weighted sum)
RISK_FLOORS = {
    "balance_reconciliation_failure": 80,
    "transaction_total_mismatch": 40,
    "missing_account_number": 35,
    "missing_ifsc": 25,
    "currency_mismatch": 50,
    "bank_identity_mismatch": 90,
    "template_watermark": 95,
}

SEVERITY_LABELS = ["Safe", "Review Required", "Suspicious", "High Risk"]

SEVERITY_LEVELS = {
    0: "Safe",
    1: "Review Required",
    2: "Suspicious",
    3: "High Risk",
}


def _score_from_findings(findings: list, score_key: str = "score") -> float:
    """Compute 0–100 confidence-weighted score from a list of finding dicts."""
    if not findings:
        return 0.0
    total = sum(f.get("risk_points", 0) * f.get("confidence", 1.0) for f in findings)
    return min(total, 100.0)


# ── Banking Authenticity ─────────────────────────────────────────────

def _banking_authenticity_score(bank_result: dict) -> Tuple[float, float, List[dict]]:
    """Derive 0–100 risk contribution from banking authenticity checks (template, identity, currency)."""
    if not bank_result:
        return 0.0, 1.0, []

    raw_findings = bank_result.get("findings", [])
    # Exclude transaction_integrity findings — they are scored separately by _financial_integrity_score
    bank_only = [f for f in raw_findings if f.get("field") != "transaction_integrity"]
    bank_name = bank_result.get("bank_name")
    confidence = bank_result.get("confidence", 1.0)
    bank_risk = min(sum(f.get("risk_points", 0) * f.get("confidence", 1.0) for f in bank_only), 100.0)

    # Categorise findings
    identity_findings = [f for f in bank_only if f.get("field") == "bank_identity"]
    template_findings = [f for f in bank_only if f.get("field") == "document_authenticity"]
    other_findings = [f for f in bank_only if f.get("field") not in ("bank_identity", "document_authenticity")]

    findings_used = []

    # ── Build all evidence lines and collect severities ──
    all_evidence_lines = []
    all_severities = set()
    total_risk = 0

    for f in template_findings:
        total_risk += f.get("risk_points", 0)
        all_severities.add(f.get("severity", "LOW"))
    for f in identity_findings:
        total_risk += f.get("risk_points", 0)
        all_severities.add(f.get("severity", "LOW"))
    for f in other_findings:
        total_risk += f.get("risk_points", 0)
        all_severities.add(f.get("severity", "LOW"))

    severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    max_severity = max(all_severities, key=lambda s: severity_order.get(s, 0)) if all_severities else "LOW"

    if template_findings:
        if any("template.net" in f.get("evidence", "").lower() for f in template_findings):
            all_evidence_lines.append("✓ TEMPLATE.NET watermark detected")
        if any("public template" in f.get("finding", "").lower() for f in template_findings):
            all_evidence_lines.append("✓ Public template source identified")

    for f in identity_findings:
        field_name = f.get("finding", "").replace("Missing ", "")
        all_evidence_lines.append(f"✓ Missing {field_name}")

    for f in other_findings:
        raw = f.get("finding", "")
        evidence_text = f.get("evidence", "")
        field = f.get("field", "")
        if field == "currency_consistency" or "currency" in raw.lower() or "non-inr" in raw.lower():
            # Extract institution and currency from evidence like "Institution: Canara Bank | Expected: INR | Detected: $"
            parts = evidence_text.split("|")
            inst = parts[0].replace("Institution:", "").strip() if len(parts) > 0 else "Bank"
            curr = parts[2].replace("Detected:", "").strip() if len(parts) > 2 else "foreign currency"
            all_evidence_lines.append(f"✓ Currency mismatch — {inst} uses {curr} instead of INR")
        elif "invoice" in raw.lower():
            all_evidence_lines.append("✓ Invoice terminology detected in statement")
        elif "balance reconciliation" in raw.lower():
            all_evidence_lines.append(f"✓ {raw[:120]}")
        elif "transaction total mismatch" in raw.lower():
            all_evidence_lines.append(f"✓ {raw[:120]}")
        else:
            all_evidence_lines.append(f"✓ {raw[:80]}")

    # Add whitelist signals as positive evidence
    whitelist = bank_result.get("whitelist_signals", [])
    for signal in whitelist:
        detail = signal.get("detail", signal.get("signal", ""))
        all_evidence_lines.append(f"✓ Whitelist: {detail} (risk -{signal.get('reduction', 0)})")

    # Consolidated snippet for the evidence field
    consolidated_snippet = "Detected Issues:\n" + "\n".join(all_evidence_lines)

    # Only flag authenticity failure when meaningful risk exists
    whitelist_reduction = sum(s.get("reduction", 0) for s in whitelist)
    effective_risk = max(0, total_risk - whitelist_reduction)
    # Use raw (pre-whitelist) risk for the gate to prevent whitelist from
    # silently suppressing findings. A single missing IFSC (10 pts) should
    # always appear.
    meaningful_risk = total_risk >= 10 or max_severity in ("HIGH", "CRITICAL")
    if (template_findings or identity_findings or other_findings) and meaningful_risk:
        # Choose appropriate severity text based on finding types
        has_serious_fraud = template_findings or any(
            f.get("field") != "bank_identity" for f in other_findings
        )
        if has_serious_fraud:
            finding_text = "Document Authenticity Validation Failed — multiple indicators of fabricated document"
        elif len(identity_findings) == 1:
            finding_text = f"Document Incomplete — {identity_findings[0].get('finding', 'Required Field Missing')}"
        else:
            finding_text = f"Document Incomplete — {len(identity_findings)} Core Banking Fields Missing"
        findings_used.append({
            "text": finding_text,
            "evidence": [EvidenceItem(
                snippet=consolidated_snippet[:500],
                field="banking_authenticity",
                confidence=confidence,
            )],
            "confidence": confidence,
            "severity": max_severity if max_severity != "LOW" else "HIGH",
        })

    return bank_risk, confidence, findings_used


# ── Financial Integrity ──────────────────────────────────────────────

def _financial_integrity_score(bank_result: dict) -> Tuple[float, float, List[dict]]:
    """Derive 0–100 risk from financial arithmetic checks (balance reconciliation, running balance, total mismatch)."""
    if not bank_result:
        return 0.0, 1.0, []
    raw_findings = bank_result.get("findings", [])
    integrity_findings = [f for f in raw_findings if f.get("field") == "transaction_integrity"]
    if not integrity_findings:
        return 0.0, 1.0, []
    total = min(sum(f.get("risk_points", 0) * f.get("confidence", 1.0) for f in integrity_findings), 100.0)
    findings_used = []
    for f in integrity_findings:
        f_conf = f.get("confidence", 1.0)
        findings_used.append({
            "text": f.get("finding", "Financial integrity issue"),
            "evidence": [EvidenceItem(snippet=f.get("evidence", "")[:200], field="financial_integrity", confidence=f_conf)],
            "confidence": f_conf,
            "severity": f.get("severity", "HIGH"),
        })
    return total, 1.0, findings_used


# ── Signature Intelligence (image-based) ─────────────────────────────

def _signature_intel_score(sig_intel: dict) -> Tuple[float, float, List[dict]]:
    """Derive 0–100 from image-based signature detection (not comparison-based)."""
    if not sig_intel:
        return 0.0, 0.0, []

    has_signatures = sig_intel.get("has_signatures", False)
    max_confidence = sig_intel.get("max_confidence", 0.0)
    sig_findings = sig_intel.get("findings", [])
    image_count = sig_intel.get("image_count", 0)

    findings_used = []
    score = 0.0  # Having a signature is neutral — no risk contribution
    for f_text in sig_findings:
        is_unavailable = "not available" in f_text.lower()
        if has_signatures and not is_unavailable:
            text = (
                f"Signature Intelligence — {f_text}. "
                f"Document contains {image_count} signature-like region(s). "
                f"Recommendation: Cross-check signature against authorised specimen."
            )
            sev = "LOW"
        elif is_unavailable:
            text = (
                f"Signature Intelligence — {f_text}. "
                f"Status: Not Available — no risk contribution."
            )
            sev = "INFO"
        else:
            text = (
                f"Signature Intelligence — {f_text}. "
                f"Recommendation: No signature-related concerns."
            )
            sev = "LOW"

        findings_used.append({
            "text": text[:200],
            "evidence": [EvidenceItem(
                snippet=f_text[:300],
                field="signature_intelligence",
                confidence=max(0.5, max_confidence) if not is_unavailable else 0.0,
            )],
            "confidence": max(0.5, max_confidence) if not is_unavailable else 0.0,
            "severity": sev,
        })

    return score, max(0.5, max_confidence), findings_used


# ── OCR Reliability ──────────────────────────────────────────────────

def _ocr_reliability_score(reliability: float) -> Tuple[float, float, List[dict]]:
    """Derive 0–100 from OCR reliability. Low OCR = reduced confidence, not risk."""
    if reliability is None:
        return 0.0, 1.0, []

    score = max(0.0, (1.0 - reliability) * 30.0)
    conf = reliability

    findings_used = []
    if reliability < 0.5:
        findings_used.append({
            "text": (
                f"OCR Reliability: Low ({reliability:.0%}). "
                f"Analysis results may be less reliable due to poor text extraction. "
                f"Consider uploading a higher-quality scan."
            ),
            "evidence": [EvidenceItem(
                snippet=f"OCR confidence: {reliability:.0%}",
                field="ocr_reliability",
                confidence=reliability,
            )],
            "confidence": reliability,
            "severity": "MEDIUM",
        })
    elif reliability < 0.8:
        findings_used.append({
            "text": (
                f"OCR Reliability: Moderate ({reliability:.0%}). "
                f"Results are usable but some text may be inaccurate."
            ),
            "evidence": [EvidenceItem(
                snippet=f"OCR confidence: {reliability:.0%}",
                field="ocr_reliability",
                confidence=reliability,
            )],
            "confidence": reliability,
            "severity": "LOW",
        })
    else:
        findings_used.append({
            "text": f"OCR Reliability: High ({reliability:.0%}). Text extraction quality is good.",
            "evidence": [EvidenceItem(
                snippet=f"OCR confidence: {reliability:.0%}",
                field="ocr_reliability",
                confidence=reliability,
            )],
            "confidence": reliability,
            "severity": "LOW",
        })

    return score, reliability, findings_used


# ── Existing Module Helpers (unchanged) ──────────────────────────────

def _xai_score(xai_findings: list) -> Tuple[float, float, List[str]]:
    """Derive 0–100 contribution and confidence from XAI findings."""
    if not xai_findings:
        return 0.0, 0.0, []

    severities = [SEVERITY_MAP.get(f.get("severity", "LOW"), 0) for f in xai_findings]
    confidences = [f.get("confidence", 0.5) for f in xai_findings]

    max_sev = max(severities) if severities else 0
    avg_conf = sum(confidences) / len(confidences) if confidences else 0.5
    high_count = sum(1 for s in severities if s >= 2)

    base = (max_sev / 3.0) * 100.0
    boost = min(high_count * 8, 30)
    score = min(base + boost, 100.0)

    findings_used = []
    for f in xai_findings:
        risk = f.get("risk_impact", "")
        rec = f.get("recommendation", "")
        plain = f.get("plain_english", f.get("finding_type", "unknown"))
        text = f"{risk} Recommendation: {rec}" if risk and rec else plain[:200]
        evidence_entries = []
        details = f.get("details", {})
        if details:
            for k, v in details.items():
                if v and k not in ("similarity_score", "threshold", "confidence_pct"):
                    evidence_entries.append(EvidenceItem(
                        snippet=str(v)[:300],
                        field=k,
                        confidence=f.get("confidence", 0.5),
                    ))
        findings_used.append({
            "text": text,
            "evidence": evidence_entries,
            "confidence": f.get("confidence", avg_conf),
            "severity": f.get("severity", "LOW"),
        })

    return score, avg_conf, findings_used


def _heatmap_score(heatmap_findings: list) -> Tuple[float, float, List[str]]:
    """Derive 0–100 contribution from heatmap/ELA regions."""
    if not heatmap_findings:
        return 0.0, 0.0, []

    confidences = [min(abs(r.get("confidence", 0)), 1.0) for r in heatmap_findings]
    reasons = [r.get("reason", "suspicious region") for r in heatmap_findings]

    n_suspicious = len(heatmap_findings)
    avg_conf = sum(confidences) / len(confidences) if confidences else 0.0

    region_factor = min(n_suspicious / 3.0, 1.0)
    score = region_factor * avg_conf * 100.0

    findings_used = []
    for i, r in enumerate(reasons):
        text = f"Visual Document Analysis — {r}. Recommendation: Review the flagged region for signs of digital alteration."
        conf = confidences[i] if i < len(confidences) else avg_conf
        findings_used.append({
            "text": text,
            "evidence": [EvidenceItem(
                snippet=r[:300],
                field="visual_region",
                confidence=conf,
            )] if r else [],
            "confidence": conf,
            "severity": "MEDIUM" if conf > 0.5 else "LOW",
        })

    return score, avg_conf, findings_used


def _signature_score(sig: dict) -> Tuple[float, float, List[str]]:
    """Derive 0–100 contribution from signature verification."""
    if not sig:
        return 0.0, 0.0, []

    sim = sig.get("similarity_score", 1.0)
    is_forgery = sig.get("is_forgery", False)
    conf = sig.get("confidence", 0.5)

    if is_forgery:
        raw = max(0.0, 1.0 - sim) * 100.0
        score = min(raw + 20, 100.0)
        finding = ("Signature Validation Alert — The submitted signature does not match "
                   "the expected signature profile. Risk Impact: High. "
                   "Recommendation: Flag for manual verification by authorised signatory.")
    else:
        score = max(0.0, (1.0 - sim) * 50.0)
        finding = ("Signature Validation — The submitted signature has been analysed. "
                   "Risk Impact: Low. "
                   "Recommendation: Proceed with standard processing.")

    return score, conf, [{"text": finding, "evidence": [], "confidence": conf, "severity": "HIGH" if is_forgery else "LOW"}]


def _compliance_score(comp: dict) -> Tuple[float, float, List[str]]:
    """Derive 0–100 contribution from compliance findings."""
    if not comp:
        return 0.0, 0.0, []

    raw_findings = comp.get("findings", [])
    overall = comp.get("overall_compliance_risk", "LOW")

    severities = [SEVERITY_MAP.get(f.get("compliance_severity", "LOW"), 0) for f in raw_findings]
    max_sev = max(severities) if severities else SEVERITY_MAP.get(overall, 0)
    critical_count = sum(1 for s in severities if s >= 3)
    high_count = sum(1 for s in severities if s >= 2)

    score = (max_sev / 3.0) * 70.0 + min(critical_count * 10 + high_count * 5, 30)
    score = min(score, 100.0)

    findings_used = []
    for f in raw_findings[:5]:
        reg = f.get("regulation", "regulation")
        desc = f.get("finding_description", "")
        text = f"Compliance Review — {desc} Reference: {reg}."
        findings_used.append({
            "text": text[:200],
            "evidence": [EvidenceItem(
                snippet=(f.get("finding_description") or f.get("finding_type") or "")[:300],
                field=f.get("finding_type", "compliance"),
                confidence=0.85,
            )],
            "confidence": 0.85,
            "severity": f.get("compliance_severity", "LOW"),
        })

    return score, 0.85, findings_used


_ANOMALY_BUSINESS_MAP = {
    "isolation_forest": {
        "alert": "Document Pattern Deviation Detected",
        "explanation": "The document exhibits characteristics that differ from typical financial documents processed by the system.",
        "recommendation": "Review alongside other findings for comprehensive assessment.",
    },
    "autoencoder": {
        "alert": "Document Structure Analysis",
        "explanation": "Multiple layout inconsistencies detected compared with expected banking document formats.",
        "recommendation": "Manual authenticity review required.",
    },
    "statistical": {
        "alert": "Financial Value Pattern Analysis",
        "explanation": "Document values have been analysed for unusual numerical patterns common in financial fraud.",
        "recommendation": "Cross-check flagged values against source records if other discrepancies exist.",
    },
}


def _anomaly_score(anom: dict) -> Tuple[float, float, List[str]]:
    """Derive 0–100 contribution from novel anomaly detection.
    Capped at 15 to prevent statistical noise from overwhelming
    concrete banking-authenticity findings on bank statements.
    """
    if not anom:
        return 0.0, 0.0, []

    fusion = anom.get("fusion_score", 0.0)
    raw_findings = anom.get("findings", [])

    score = min(fusion * 100.0, 5.0)

    findings_used = []
    for f in raw_findings:
        method = f.get("method", "unknown")
        severity = f.get("severity", "LOW")
        f_conf = f.get("confidence", 0.5)
        if severity in ("MEDIUM", "HIGH", "CRITICAL"):
            template = _ANOMALY_BUSINESS_MAP.get(method, {})
            if template:
                severity_note = f"Risk Impact: {severity.title()}"
                text = f"{template['alert']} — {template['explanation']} {severity_note}. Recommendation: {template['recommendation']}"
            else:
                text = f"Document analysis completed. Recommendation: No immediate action required."
            findings_used.append({
                "text": text,
                "evidence": [EvidenceItem(
                    snippet=f.get("explanation", "")[:300],
                    field=f"anomaly.{method}",
                    confidence=f_conf,
                )] if f.get("explanation") else [],
                "confidence": f_conf,
                "severity": severity,
            })

    conf = sum(f.get("confidence", 0) for f in raw_findings) / max(len(raw_findings), 1)

    return score, conf, findings_used


def _compute_counterfactual(
    findings: list, risk_score: int,
    has_account_missing: bool, has_ifsc_missing: bool,
    has_balance_issue: bool, has_txn_issue: bool,
    has_bank_conflict: bool, has_currency_issue: bool,
) -> list[dict]:
    """Show what the decision would be if each issue were fixed.
    Banks love this — auditors can understand every score component.
    """
    results = []
    base = risk_score

    if has_account_missing:
        results.append({
            "scenario": "If account number were present",
            "estimated_risk": max(0, base - 35),
            "impact": "-35 pts",
        })
    if has_ifsc_missing:
        results.append({
            "scenario": "If IFSC code were present",
            "estimated_risk": max(0, base - 25),
            "impact": "-25 pts",
        })
    if has_balance_issue:
        results.append({
            "scenario": "If balance reconciliation passed",
            "estimated_risk": max(0, base - 30),
            "impact": "-30 pts (from penalty + risk floor)",
        })
    if has_txn_issue:
        results.append({
            "scenario": "If transaction totals matched",
            "estimated_risk": max(0, base - 20),
            "impact": "-20 pts",
        })
    if has_bank_conflict:
        results.append({
            "scenario": "If bank identity were consistent",
            "estimated_risk": max(0, base - 50),
            "impact": "-50 pts (from penalty + combination bonus + floor)",
        })
    if has_currency_issue:
        results.append({
            "scenario": "If currency were INR",
            "estimated_risk": max(0, base - 20),
            "impact": "-20 pts",
        })

    # Combined best case
    total_deduction = sum(
        r["estimated_risk"] for r in results
    )
    # Overestimate protection: deduct only up to base
    best_case = max(0, base - abs(base - min(r["estimated_risk"] for r in results)) if results else base)
    best_case = max(0, min(r["estimated_risk"] for r in results)) if results else base
    results.append({
        "scenario": "If all issues were resolved",
        "estimated_risk": best_case,
        "impact": f"Best case: {best_case} (could be APPROVE)",
    })

    return results


def aggregate_risks(input_data: AggregationInput) -> AggregationResponse:
    """Combine all module outputs into a single 0–100 risk score."""
    logger.info("Risk aggregation started", input_fields=input_data.model_dump(exclude_none=True).keys())

    # --- Compute per-module scores ---
    modules = {}

    bank_score, bank_conf, bank_findings = _banking_authenticity_score(input_data.banking_result or {})
    modules["banking_authenticity"] = {"score": bank_score, "conf": bank_conf, "findings": bank_findings, "label": "Document Authenticity"}

    fin_score, fin_conf, fin_findings = _financial_integrity_score(input_data.banking_result or {})
    modules["financial_integrity"] = {"score": fin_score, "conf": fin_conf, "findings": fin_findings, "label": "Financial Integrity"}

    sig_intel_score, sig_intel_conf, sig_intel_findings = _signature_intel_score(input_data.signature_intel_result or {})
    modules["signature"] = {"score": sig_intel_score, "conf": sig_intel_conf, "findings": sig_intel_findings, "label": "Signature Intelligence"}

    ocr_score, ocr_conf, ocr_findings = _ocr_reliability_score(input_data.ocr_reliability)
    modules["ocr_reliability"] = {"score": ocr_score, "conf": ocr_conf, "findings": ocr_findings, "label": "OCR Reliability"}

    xai_score, xai_conf, xai_findings = _xai_score(input_data.xai_findings or [])
    modules["xai"] = {"score": xai_score, "conf": xai_conf, "findings": xai_findings, "label": "Document Metadata & Content"}

    anom_score, anom_conf, anom_findings = _anomaly_score(input_data.anomaly_result or {})
    modules["anomaly"] = {"score": anom_score, "conf": anom_conf, "findings": anom_findings, "label": "Behavioural Pattern Analysis"}

    comp_score, comp_conf, comp_findings = _compliance_score(input_data.compliance_result or {})
    modules["compliance"] = {"score": comp_score, "conf": comp_conf, "findings": comp_findings, "label": "AML & Compliance"}

    # Apply whitelist reduction (capped at 15% or 10 pts, whichever is smaller)
    # Never let whitelist cancel serious fraud
    whitelist = (input_data.banking_result or {}).get("whitelist_signals", [])
    raw_bank_score = modules["banking_authenticity"]["score"]
    whitelist_reduction = sum(s.get("reduction", 0) for s in whitelist)
    capped_reduction = min(whitelist_reduction, raw_bank_score * 0.15, 10.0)
    modules["banking_authenticity"]["score"] = max(0.0, raw_bank_score - capped_reduction)
    if whitelist_reduction > capped_reduction:
        logger.warning("WHITELIST_CAPPED", raw=raw_bank_score, requested=whitelist_reduction, applied=capped_reduction)

    # Determine which modules are present
    present_keys = set()
    if input_data.xai_findings:
        present_keys.add("xai")
    if input_data.anomaly_result:
        present_keys.add("anomaly")
    if input_data.banking_result:
        present_keys.add("banking_authenticity")
        if any(f.get("field") == "transaction_integrity" for f in (input_data.banking_result.get("findings") or [])):
            present_keys.add("financial_integrity")
    if input_data.signature_intel_result:
        present_keys.add("signature")
    if input_data.ocr_reliability is not None:
        present_keys.add("ocr_reliability")
    if input_data.compliance_result:
        present_keys.add("compliance")

    if not present_keys:
        return AggregationResponse(
            risk_score=0, severity="Safe", verdict="NO SIGNIFICANT ISSUES DETECTED",
            findings=[], recommendations=["No analysis data provided."],
            sources_used=[],
        )

    # Weighted sum using FINAL_WEIGHTS (weights sum to 1.0, no normalization needed)
    weighted_sum = 0.0
    all_findings: List[AggregatedFinding] = []
    all_recommendations: List[str] = []
    risk_categories: List[RiskCategory] = []

    for key in present_keys:
        mod = modules[key]
        weight = FINAL_WEIGHTS[key]
        contribution = mod["score"] * weight
        weighted_sum += contribution

        risk_categories.append(RiskCategory(
            key=key,
            label=mod["label"],
            score=round(mod["score"], 1),
            confidence=round(mod["conf"], 3),
            findings_count=len(mod["findings"]),
            weight=round(weight, 3),
        ))

        # Generate findings for this module
        if mod["score"] > 15:
            mod_severity = "HIGH" if mod["score"] > 60 else "MEDIUM" if mod["score"] > 30 else "LOW"
            if mod["findings"]:
                for finding_dict in mod["findings"]:
                    finding_text = finding_dict.get("text", "")
                    evidence_list = finding_dict.get("evidence", [])
                    f_conf = finding_dict.get("confidence", 0.0)
                    f_severity = finding_dict.get("severity", mod_severity)
                    all_findings.append(AggregatedFinding(
                        finding=finding_text[:200],
                        category=key,
                        severity=f_severity,
                        score_contribution=round(contribution, 1),
                        evidence=evidence_list,
                        confidence=round(f_conf, 3),
                    ))
            else:
                label = mod.get("label", key.title())
                if mod["score"] > 60:
                    text = f"{label} flagged anomalies"
                else:
                    text = f"{label} — minor deviations detected"
                all_findings.append(AggregatedFinding(
                    finding=text,
                    category=key,
                    severity=mod_severity,
                    score_contribution=round(contribution, 1),
                    confidence=round(mod["conf"], 3),
                ))
        elif mod["score"] >= 1:
            if mod["findings"]:
                for finding_dict in mod["findings"]:
                    severity = finding_dict.get("severity", "LOW")
                    if severity in ("MEDIUM", "HIGH", "CRITICAL"):
                        f_conf = finding_dict.get("confidence", 0.0)
                        all_findings.append(AggregatedFinding(
                            finding=finding_dict.get("text", "")[:200],
                            category=key,
                            severity=severity,
                            score_contribution=round(contribution, 1),
                            evidence=finding_dict.get("evidence", []),
                            confidence=round(f_conf, 3),
                        ))

    # ── Detect Conditions ──────────────────────────────────────────────
    bank_findings_list = (input_data.banking_result or {}).get("findings", [])
    bank_fields = {f.get("field") for f in bank_findings_list}

    # ── Add individual raw bank findings to all_findings ──────────────
    if "banking_authenticity" in present_keys:
        for bf in bank_findings_list:
            bf_text = bf.get("finding", "")
            bf_severity = bf.get("severity", "LOW")
            if bf_text and bf_severity in ("MEDIUM", "HIGH", "CRITICAL"):
                if not any(f.finding == bf_text[:200] for f in all_findings):
                    all_findings.append(AggregatedFinding(
                        finding=bf_text[:200],
                        category="banking_authenticity",
                        severity=bf_severity,
                        score_contribution=0,
                        evidence=[],
                        confidence=1.0,
                    ))

    has_template = any(f.get("risk_points", 0) >= 40 and f.get("field") == "document_authenticity"
                       for f in bank_findings_list)
    has_currency_mismatch = "currency_consistency" in bank_fields
    has_balance_mismatch = any(f.get("field") == "transaction_integrity"
                               and "balance" in f.get("finding", "").lower()
                               and "reconciliation failure" in f.get("finding", "").lower()
                               for f in bank_findings_list)
    has_account_missing = any("account number" in f.get("finding", "").lower() and "missing" in f.get("finding", "").lower()
                              for f in bank_findings_list)
    has_ifsc_missing = any("ifsc" in f.get("finding", "").lower() and "missing" in f.get("finding", "").lower()
                           for f in bank_findings_list)
    has_bank_conflict = any("bank identity conflict" in f.get("finding", "").lower()
                            for f in bank_findings_list)
    has_balance_reconciliation = any("reconciliation failure" in f.get("finding", "").lower()
                                     and "unable to verify" not in f.get("finding", "").lower()
                                     for f in bank_findings_list)
    has_transaction_total_mismatch = any("transaction total mismatch" in f.get("finding", "").lower()
                                        for f in bank_findings_list)
    has_metadata_missing = any("missing pdf metadata" in f.get("finding", "").lower()
                               for f in bank_findings_list)
    has_layout_mismatch = any("layout structure mismatch" in f.get("finding", "").lower()
                              for f in bank_findings_list)
    has_low_quality_ocr = (input_data.ocr_reliability or 0.0) < 0.5

    # ── Evidence Quality ────────────────────────────────────────────
    # Composite metric: how much we trust the extraction itself.
    # Derived from bank detection confidence, OCR quality, parser quality, and balance extraction.
    bank_result = input_data.banking_result or {}
    bank_confidence = bank_result.get("bank_confidence", 0.0) or 0.0
    extraction_quality = bank_result.get("extraction_quality", 1.0) or 1.0
    ocr_q = input_data.ocr_reliability or 1.0
    parser_conf = bank_result.get("confidence", 1.0) or 1.0
    evidence_quality = round(0.30 * ocr_q + 0.25 * parser_conf + 0.25 * extraction_quality + 0.20 * bank_confidence, 2)
    logger.info("EVIDENCE_QUALITY", evidence_quality=evidence_quality,
                ocr=ocr_q, parser=parser_conf, extraction=extraction_quality, bank=bank_confidence)

    # ── Status-Aware Detection ──────────────────────────────────────
    # Respect UNKNOWN status: missing data is NOT evidence of fraud
    unknown_findings = [f for f in bank_findings_list if f.get("status") == "UNKNOWN"]

    # ── Decision Path (per-finding score contribution) ──────────────
    decision_path = []
    for f in bank_findings_list:
        rp = f.get("risk_points", 0)
        if rp > 0:
            decision_path.append({
                "finding": f.get("finding", "")[:120],
                "severity": f.get("severity", "LOW"),
                "points_added": rp,
                "status": f.get("status", "FAIL"),
            })

    # ── Risk Score Base ─────────────────────────────────────────────
    original_weighted = round(weighted_sum, 1)
    risk_score = round(min(weighted_sum, 100.0))

    # ── Severity Weights (only for findings with FAIL status) ───────
    severity_bonus = 0
    for f in bank_findings_list:
        if f.get("status") != "UNKNOWN":
            severity_bonus += SEVERITY_WEIGHTS.get(f.get("severity", "LOW"), 0)
    risk_score += min(severity_bonus, 40)

    # ── Combination Bonuses ─────────────────────────────────────────
    if has_ifsc_missing and has_account_missing:
        risk_score += 20
    if (has_balance_reconciliation or has_balance_mismatch) and has_transaction_total_mismatch:
        risk_score += 30
    if has_template and has_currency_mismatch:
        risk_score += 40
    if has_bank_conflict and has_template:
        risk_score += 50

    # ── Risk Floors (dict-driven) ───────────────────────────────────
    finding_to_floor = {
        "balance_reconciliation_failure": has_balance_reconciliation or has_balance_mismatch,
        "transaction_total_mismatch": has_transaction_total_mismatch,
        "missing_account_number": has_account_missing,
        "missing_ifsc": has_ifsc_missing,
        "currency_mismatch": has_currency_mismatch,
        "bank_identity_mismatch": has_bank_conflict,
        "template_watermark": has_template,
    }
    for condition_name, active in finding_to_floor.items():
        if active:
            risk_score = max(risk_score, RISK_FLOORS.get(condition_name, 0))

    risk_score = min(round(risk_score), 100)

    # ── Evidence-Quality Gate ──
    evidence_too_low_for_reject = evidence_quality < 0.6
    evidence_too_low_for_approve = evidence_quality < 0.3
    has_extraction_failures = len(unknown_findings) > 0

    # Hard reject signals (gated by evidence quality & status)
    hard_reject_raw = (
        has_balance_reconciliation or has_balance_mismatch
        or has_currency_mismatch
        or has_transaction_total_mismatch
    )
    hard_reject_bank_conflict = has_bank_conflict and bank_confidence > 0.9
    hard_reject = hard_reject_raw or hard_reject_bank_conflict

    strong_review = has_template
    critical_findings = [f for f in bank_findings_list if f.get("severity") == "CRITICAL"]
    high_findings = [f for f in bank_findings_list if f.get("severity") == "HIGH"]
    critical_count = len(critical_findings)
    high_count = len(high_findings)

    # ── Decision & Verdict ──
    override_reason = None
    if evidence_too_low_for_reject and (hard_reject or (strong_review and critical_count >= 2)):
        override_reason = "Review — evidence quality too low for confident rejection"
    elif has_extraction_failures and evidence_quality < 0.7:
        override_reason = "Manual Review Required — transaction extraction failed or unreliable"
    elif hard_reject:
        parts = []
        if has_balance_reconciliation or has_balance_mismatch:
            parts.append("balance mismatch")
        if has_transaction_total_mismatch:
            parts.append("transaction total mismatch")
        if has_bank_conflict:
            parts.append("bank identity conflict")
        if has_currency_mismatch:
            parts.append("currency mismatch")
        override_reason = "Reject — " + ", ".join(parts)
    elif strong_review and critical_count >= 2:
        override_reason = "Reject — template watermark with multiple critical findings"
    elif risk_score < 20 and not evidence_too_low_for_approve:
        override_reason = "Approve — no significant issues"
    else:
        parts = []
        if has_account_missing:
            parts.append("missing account number")
        if has_ifsc_missing:
            parts.append("missing IFSC code")
        if has_metadata_missing:
            parts.append("missing PDF metadata")
        if has_low_quality_ocr:
            parts.append("low quality OCR")
        if evidence_too_low_for_reject:
            parts.append("low evidence quality")
        if has_extraction_failures:
            parts.append("transaction extraction issues")
        override_reason = "Review — " + ", ".join(parts) if parts else "Review — minor issues"

    # Final Classification
    if evidence_too_low_for_reject and (hard_reject or (strong_review and critical_count >= 2)):
        risk_score = max(risk_score, 30)
        decision = "REVIEW"
        verdict = "MANUAL REVIEW REQUIRED — insufficient evidence quality to reject"
    elif has_extraction_failures and evidence_quality < 0.7:
        risk_score = max(risk_score, 25)
        decision = "REVIEW"
        verdict = "MANUAL REVIEW REQUIRED — transaction extraction issues"
    elif hard_reject:
        risk_score = max(risk_score, 75)
        decision = "REJECT"
        verdict = "LIKELY FABRICATED DOCUMENT"
    elif strong_review and critical_count >= 2:
        risk_score = max(risk_score, 60)
        decision = "REJECT"
        verdict = "LIKELY FABRICATED DOCUMENT"
    elif strong_review or critical_count >= 1 or high_count >= 3:
        risk_score = max(risk_score, 30)
        decision = "REVIEW"
        verdict = "ANOMALOUS — REVIEW RECOMMENDED"
    elif risk_score < 20 and not evidence_too_low_for_approve:
        decision = "APPROVE"
        verdict = "NO SIGNIFICANT ISSUES DETECTED"
    else:
        risk_score = max(risk_score, 25)
        decision = "REVIEW"
        verdict = "ANOMALOUS — REVIEW RECOMMENDED"

    # ── Detection Confidence vs Fraud Risk (split) ──────────────────
    # Detection confidence = how sure we are about the data extraction
    detection_confidence = round(evidence_quality * 100)
    # Fraud risk = the risk_score (how risky the document is)
    fraud_risk = risk_score
    # Weighted confidence for backward compat
    fail_findings = [f for f in bank_findings_list if f.get("status") != "UNKNOWN"]
    evidence_count = len(fail_findings)
    fail_critical = sum(1 for f in fail_findings if f.get("severity") == "CRITICAL")
    fail_high = sum(1 for f in fail_findings if f.get("severity") == "HIGH")
    fraud_confidence = min(
        10 + evidence_count * 12 + fail_critical * 25 + fail_high * 12,
        99
    )
    if evidence_count > 0:
        fraud_confidence = max(fraud_confidence, 10)

    # ── Counterfactual Analysis ─────────────────────────────────────
    counterfactual = _compute_counterfactual(
        bank_findings_list, risk_score, has_account_missing, has_ifsc_missing,
        has_balance_reconciliation or has_balance_mismatch,
        has_transaction_total_mismatch, has_bank_conflict, has_currency_mismatch,
    )

    # Override reason finding
    if override_reason:
        logger.info("RISK_OVERRIDE", reason=override_reason,
                    original_score=round(weighted_sum, 1),
                    overridden_score=risk_score)
        if not any(f.finding == override_reason[:200] for f in all_findings):
            all_findings.append(AggregatedFinding(
                finding=override_reason[:200],
                category="banking_authenticity",
                severity="MEDIUM",
                score_contribution=0,
                evidence=[],
                confidence=1.0,
            ))

    # --- Recommendations ---
    if decision == "REJECT":
        all_recommendations.append("1. Reject submitted statement — high-confidence fabrication detected.")
        all_recommendations.append("2. Request original bank-issued PDF directly from the issuing bank.")
        all_recommendations.append("3. Verify account ownership with issuing bank through official channels.")
        all_recommendations.append("4. Compare against historical statements on file for format inconsistencies.")
        all_recommendations.append("5. Escalate to fraud operations team for case registration.")
    elif decision == "REVIEW":
        if has_extraction_failures:
            all_recommendations.append("1. Manual review required — transaction extraction failed or unreliable.")
            all_recommendations.append("2. Verify document quality (scan/PDF) and re-upload if needed.")
        else:
            all_recommendations.append("1. Schedule manual review within standard SLA.")
        all_recommendations.append("2. Verify document authenticity with issuing bank if suspicion persists.")
        all_recommendations.append("3. Cross-check high-value transactions against bank records.")
    else:
        all_recommendations.append("Document appears to be a low-risk submission. Standard processing can proceed.")

    if override_reason and "IFSC" in override_reason:
        all_recommendations.append("⚠ IFSC code could not be verified — manual review recommended before approval.")
    if override_reason and "account number" in override_reason.lower():
        all_recommendations.append("⚠ Account number could not be verified — cross-check with bank records.")
    if has_transaction_total_mismatch:
        all_recommendations.append("⚠ Transaction totals do not match individual entries — verify arithmetic with issuing bank.")
    if has_balance_reconciliation or has_balance_mismatch:
        all_recommendations.append("⚠ Balance reconciliation failure — opening + credits − debits does not equal closing.")
    if "anomaly" in present_keys and modules["anomaly"]["score"] > 50:
        all_recommendations.append("Review flagged anomaly features — patterns may indicate novel fraud technique.")

    # ── Severity Band ──
    severity = "Safe"
    if decision == "REJECT":
        severity = "High Risk"
    elif decision == "REVIEW":
        severity = "Suspicious" if risk_score >= 50 else "Review Required"

    logger.info("Risk aggregation complete",
                risk_score=risk_score, severity=severity,
                detection_confidence=detection_confidence,
                fraud_risk=fraud_risk, decision=decision,
                sources=list(present_keys))

    authenticity_score = max(0, 100 - risk_score)

    # ── Evidence Summary ──
    top_evidence = sorted(all_findings, key=lambda x: x.score_contribution, reverse=True)[:5]

    # ── Fabrication Indicators ──
    indicator_items = []
    for f in bank_findings_list:
        txt = f.get("finding", "")
        if txt and f.get("risk_points", 0) >= 5 and "template match" not in txt.lower():
            indicator_items.append(txt)
    fabrication_indicators = {"detected": len(indicator_items), "total": len(indicator_items), "items": indicator_items}

    # ── Trust Layer ──
    trust_math = 100
    trust_template = 100
    trust_metadata = 100
    trust_integrity = 100
    if has_balance_reconciliation or has_balance_mismatch:
        trust_math -= 50
    if has_transaction_total_mismatch:
        trust_math -= 30
    if any("running balance" in f.get("finding", "").lower() for f in bank_findings_list):
        trust_math -= 20
    if has_template:
        trust_template -= 40
    if has_layout_mismatch:
        trust_template -= 20
    if any("invoice" in f.get("finding", "").lower() for f in bank_findings_list):
        trust_template -= 25
    if has_metadata_missing:
        trust_metadata -= 30
    for f in bank_findings_list:
        if "suspicious pdf producer" in f.get("finding", "").lower():
            trust_metadata -= 20
        if "modified after creation" in f.get("finding", "").lower():
            trust_metadata -= 15
    if has_account_missing:
        trust_integrity -= 35
    if has_ifsc_missing:
        trust_integrity -= 20
    if has_bank_conflict:
        trust_integrity -= 40
    if has_currency_mismatch:
        trust_integrity -= 50
    trust_scores = {
        "Math Consistency": max(0, trust_math),
        "Template Match": max(0, trust_template),
        "Bank Metadata": max(0, trust_metadata),
        "Transaction Integrity": max(0, trust_integrity),
    }

    # ── Decision Confidence (explainability) ──
    total_risk_for_confidence = max(risk_score, 1)
    decision_confidence_items = []
    for f in all_findings:
        contrib_pct = round((f.score_contribution / total_risk_for_confidence) * 100, 1)
        if contrib_pct > 0:
            decision_confidence_items.append({
                "finding": f.finding[:80],
                "contribution_pct": contrib_pct,
                "severity": f.severity,
            })
    decision_confidence = {
        "decision": decision,
        "overall_confidence": fraud_confidence,
        "findings_breakdown": sorted(decision_confidence_items, key=lambda x: x["contribution_pct"], reverse=True),
    }

    # ── Fraud DNA ──
    fraud_dna = {
        "Authenticity": max(0, 100 - risk_score),
        "Integrity": max(0, trust_integrity),
        "Metadata": max(0, trust_metadata),
        "Layout": max(0, trust_template),
        "Financial": max(0, trust_math),
    }

    # ── Review Priority ──
    if decision == "REJECT":
        review_priority = "CRITICAL"
    elif decision == "REVIEW":
        if critical_count >= 1:
            review_priority = "HIGH"
        elif high_count >= 2:
            review_priority = "HIGH"
        elif has_account_missing or has_ifsc_missing:
            review_priority = "MEDIUM"
        else:
            review_priority = "LOW"
    else:
        review_priority = "LOW"

    # ── Fraud Type Classification ──
    fraud_type = None
    if has_balance_reconciliation or has_balance_mismatch:
        if has_transaction_total_mismatch:
            fraud_type = "Financial Statement Fraud"
        else:
            fraud_type = "Balance Manipulation"
    elif has_template:
        fraud_type = "Template-Based Fabrication"
    elif has_bank_conflict and bank_confidence > 0.9:
        fraud_type = "Identity Mismatch"
    elif has_bank_conflict:
        fraud_type = "Possible Identity Mismatch (low confidence)"
    elif has_currency_mismatch:
        fraud_type = "Currency Inconsistency"
    elif has_account_missing or has_ifsc_missing:
        fraud_type = "Incomplete Documentation"
    elif any("salary" in f.get("finding", "").lower() for f in bank_findings_list):
        fraud_type = "Salary Inflation"
    elif any("structuring" in f.get("finding", "").lower() for f in bank_findings_list):
        fraud_type = "AML Structuring"

    # ── Fraud Cost Estimate ──────────────────────────────────────────
    fraud_cost_estimate = None
    bank_result = input_data.banking_result or {}
    est_loss = bank_result.get("estimated_fraud_loss")
    if est_loss and est_loss > 0:
        fraud_cost_estimate = {
            "estimated_exposure": round(est_loss, 2),
            "currency": "INR",
            "breakdown": {
                "balance_mismatch_loss": round(bank_result.get("estimated_fraud_loss", 0), 2),
            },
            "note": "Estimated potential exposure based on detected discrepancies",
        }
    elif has_balance_reconciliation or has_balance_mismatch:
        total_credits = sum(t.get("credit", 0) or 0 for t in (bank_result.get("findings") or []))
        fraud_cost_estimate = {
            "estimated_exposure": 0,
            "currency": "INR",
            "breakdown": {},
            "note": "Balance inconsistency detected — manual verification required for loss estimation",
        }

    # ── Case-Based Reasoning ─────────────────────────────────────────
    similar_cases = []
    try:
        case_features = build_case_features(input_data.banking_result or {})
        case_store = get_case_store()
        similar_cases = case_store.find_similar(case_features, top_k=3)
    except Exception:
        logger.warning("CASE_REASONING_FAILED", exc_info=True)

    logger.info("=" * 80)
    logger.info("FINAL SCAN RESULT")
    logger.info("risk_score=%s severity=%s verdict=%s decision=%s", risk_score, severity, verdict, decision)
    logger.info("authenticity_score=%s fraud_confidence=%s", authenticity_score, fraud_confidence)
    logger.info("override_reason=%s", override_reason)
    logger.info("review_priority=%s fraud_type=%s", review_priority, fraud_type)
    logger.info("trust_scores=%s", trust_scores)
    logger.info("FINDINGS:")
    for f in all_findings:
        logger.info("  [%s] %s (score=%.1f, conf=%.2f)", f.severity, f.finding, f.score_contribution, f.confidence)
        for ev in f.evidence:
            logger.info("    evidence: %s", ev.snippet[:200])
    logger.info("FABRICATION_INDICATORS: %s", fabrication_indicators)
    logger.info("=" * 80)

    return AggregationResponse(
        risk_score=risk_score,
        severity=severity,
        verdict=verdict,
        fabrication_indicators=fabrication_indicators,
        authenticity_score=authenticity_score,
        fraud_confidence=fraud_confidence,
        detection_confidence=detection_confidence,
        fraud_risk=fraud_risk,
        decision=decision,
        override_reason=override_reason,
        original_score=original_weighted,
        findings=all_findings,
        risk_categories=risk_categories,
        recommendations=all_recommendations,
        sources_used=sorted(present_keys),
        trust_scores=trust_scores,
        decision_confidence=decision_confidence,
        fraud_dna=fraud_dna,
        review_priority=review_priority,
        fraud_type=fraud_type,
        fraud_cost_estimate=fraud_cost_estimate,
        similar_cases=similar_cases or None,
        evidence_quality=evidence_quality,
        decision_path=decision_path,
        counterfactual=counterfactual,
    )
