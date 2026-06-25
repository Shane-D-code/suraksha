"""
Pydantic schemas for the final risk aggregation engine.

Combines outputs from six analysis pipelines into a unified
0–100 risk score with severity bands, combined findings, and
actionable recommendations.
"""
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime


class EvidenceItem(BaseModel):
    snippet: str = Field(..., description="Exact text or value extracted from document")
    page_ref: Optional[str] = Field(None, description="Page number or section reference")
    field: Optional[str] = Field(None, description="Specific field or column name")
    expected: Optional[str] = Field(None, description="Expected value or format")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence in this evidence")


class AggregatedFinding(BaseModel):
    finding: str = Field(..., description="Short description of the finding")
    category: str = Field(..., description="Source pipeline: metadata, ocr, ela, signature, compliance, anomaly")
    severity: str = Field(default="MEDIUM", description="LOW / MEDIUM / HIGH / CRITICAL")
    score_contribution: float = Field(..., ge=0.0, le=100.0, description="Points this finding contributed to the final score")
    evidence: List[EvidenceItem] = Field(default_factory=list, description="Supporting evidence snippets")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence in this finding")


class RiskCategory(BaseModel):
    key: str = Field(..., description="Unique category key")
    label: str = Field(..., description="Human-readable category name")
    score: float = Field(..., ge=0.0, le=100.0, description="Category score 0–100")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in category score")
    findings_count: int = Field(default=0, description="Number of findings in this category")
    weight: float = Field(default=0.0, ge=0.0, le=1.0, description="Weight contribution to final score")


class AggregationResponse(BaseModel):
    risk_score: int = Field(..., ge=0, le=100, description="Unified risk score 0–100")
    severity: str = Field(..., description="Safe / Review Required / Suspicious / High Risk")
    authenticity_score: Optional[float] = Field(None, ge=0, le=100, description="Document authenticity score 0–100 (100 = fully authentic, 0 = fabricated)")
    fraud_confidence: int = Field(default=0, ge=0, le=100, description="Confidence that document is fraudulent 0–100% (legacy — see detection_confidence + fraud_risk)")
    detection_confidence: Optional[int] = Field(None, ge=0, le=100, description="Confidence in the extraction/detection itself 0–100% (how sure are we of the data)")
    fraud_risk: Optional[int] = Field(None, ge=0, le=100, description="How risky the document appears 0–100 (same as risk_score, explicit label)")
    decision: str = Field(default="REVIEW", description="Recommended decision: APPROVE / REVIEW / ESCALATE / REJECT")
    findings: List[AggregatedFinding] = Field(default_factory=list, description="Combined findings from all pipelines")
    risk_categories: List[RiskCategory] = Field(default_factory=list, description="Per-category risk breakdown")
    recommendations: List[str] = Field(default_factory=list, description="Aggregated recommended actions")
    verdict: Optional[str] = Field(None, description="Human-readable verdict label (e.g. 'LIKELY FABRICATED DOCUMENT')")
    fabrication_indicators: Optional[dict] = Field(None, description="Fabrication indicator counts { detected: N, total: N, items: [...] }")
    override_reason: Optional[str] = Field(None, description="Reason for risk score override if escalation rules triggered")
    original_score: Optional[float] = Field(None, ge=0.0, le=100.0, description="Original weighted score before override")
    extracted_fields: Optional[dict] = Field(None, description="Key-value pairs of fields extracted from the document (bank name, account, IFSC, balances, etc.)")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    sources_used: List[str] = Field(default_factory=list, description="Which pipelines contributed to the score")

    # ── Evidence Quality ──────────────────────────────────────────────
    evidence_quality: Optional[float] = Field(None, ge=0.0, le=1.0, description="Overall evidence quality 0–1 (low → cannot make high-confidence decisions)")

    # ── Decision Path (explainability) ────────────────────────────────
    decision_path: Optional[List[dict]] = Field(None, description="Per-finding score breakdown showing exactly how each finding contributed")

    # ── Counterfactual Analysis ───────────────────────────────────────
    counterfactual: Optional[List[dict]] = Field(None, description="What-if analysis: estimated risk if each issue were resolved")

    # ── Trust Layer ──────────────────────────────────────────────────
    trust_scores: Optional[dict] = Field(None, description="Per-category trust breakdown: { category: score% }")

    # ── Decision Confidence ──────────────────────────────────────────
    decision_confidence: Optional[dict] = Field(None, description="Decision confidence breakdown with per-finding contribution %")

    # ── Fraud DNA ────────────────────────────────────────────────────
    fraud_dna: Optional[dict] = Field(None, description="Visual fraud DNA categories with 0-100 scores per dimension")

    # ── Review Priority ──────────────────────────────────────────────
    review_priority: Optional[str] = Field(None, description="Analyst queue priority: CRITICAL / HIGH / MEDIUM / LOW")

    # ── Fraud Type Classification ────────────────────────────────────
    fraud_type: Optional[str] = Field(None, description="Classified fraud type if detected")

    # ── Fraud Cost Estimate ──────────────────────────────────────────
    fraud_cost_estimate: Optional[dict] = Field(None, description="Estimated financial exposure breakdown")

    # ── Case-Based Reasoning ─────────────────────────────────────────
    similar_cases: Optional[List[dict]] = Field(None, description="Similar past cases with outcomes for precedent-based decision support")

    # ── Evidence Correlation (Feature 1) ──────────────────────────────
    evidence_correlation: Optional[dict] = Field(None, description="Correlated evidence across all pipeline stages: root_cause, fraud_chain, confidence, primary_reason")

    # ── Pipeline Timeline (Feature 2) ─────────────────────────────────
    timeline: Optional[List[dict]] = Field(None, description="Per-stage timing: name, duration_ms, status")

    # ── Module Health Report (Feature 6) ──────────────────────────────
    module_health: Optional[List[dict]] = Field(None, description="Diagnostic health report per module: name, status, time_ms, errors")

    # ── Root Cause (Feature 4) ────────────────────────────────────────
    root_cause: Optional[str] = Field(None, description="Concise root cause explanation for the investigation outcome")

    # ── Fraud Categories (Feature 5) ──────────────────────────────────
    fraud_categories: Optional[dict] = Field(None, description="Classified fraud categories: primary, secondary")

    # ── Decision Card (Feature 7) ─────────────────────────────────────
    decision_card: Optional[dict] = Field(None, description="Decision summary card: decision, risk, confidence, primary_reason, review_team")

    # ── Pipeline Progress (Feature 10) ────────────────────────────────
    pipeline_progress: Optional[List[dict]] = Field(None, description="Pipeline stage completion status for frontend animation")

    # ── Investigation Summary (Feature 11) ────────────────────────────
    investigation_summary: Optional[dict] = Field(None, description="Full investigation report: executive_summary, technical_summary, evidence_summary, business_impact, recommended_action")

    # ── Enriched Findings (Features 3 + 8: Confidence Engine + Evidence Weighting) ──
    enriched_findings: Optional[List[dict]] = Field(None, description="Every finding enriched with confidence, severity, evidence_strength, weight, and source")

    # ── Financial Explanation (Feature 9) ─────────────────────────────
    financial_explanation: Optional[dict] = Field(None, description="Financial breakdown when integrity passes: opening, credits, debits, closing, formula verification")

    # ── Investigation Narrative ────────────────────────────────────────
    investigation_narrative: Optional[dict] = Field(None, description="Deterministic investigation story: executive_summary, technical_summary, business_summary, recommendation_reason")

    # ── Evidence Chain (cause-effect correlation) ──────────────────────
    evidence_chain: Optional[dict] = Field(None, description="Cause-effect evidence chain: fraud_chain (list of {cause, effect}), root_cause, confidence")

    # ── Rule Trace ─────────────────────────────────────────────────────
    rule_trace: Optional[List[dict]] = Field(None, description="Append-only trace of every rule that fired: {rule_id, module, reason, impact, final_effect}")

    # ── Risk Waterfall ─────────────────────────────────────────────────
    risk_waterfall: Optional[List[dict]] = Field(None, description="Cumulative risk visualization metadata: [{stage, score|delta, total}]")

    # ── Evidence Tree ──────────────────────────────────────────────────
    evidence_tree: Optional[dict] = Field(None, description="Hierarchical evidence tree grouping findings: {categories: [{label, status, checks}]}")

    # ── Fraud Fingerprint ──────────────────────────────────────────────
    fraud_fingerprint: Optional[str] = Field(None, description="Deterministic fraud fingerprint string (e.g. AUTH3-OCR1-META2-AML0-COMP0-FIN1-ANOM0-SIG0-PAT0)")

    # ── Executive Investigation Report ─────────────────────────────────
    executive_report: Optional[dict] = Field(None, description="Comprehensive executive investigation report: executive_summary, technical_findings, evidence_summary, timeline_overview, compliance, recommendations, decision")


class AggregationInput(BaseModel):
    """Wraps the output of each detection module for aggregation."""

    xai_findings: Optional[List[dict]] = Field(
        None, description="List of XAI explanation dicts from POST /xai/explain (covers metadata + OCR). "
        "Each dict must have: severity, confidence"
    )
    heatmap_findings: Optional[List[dict]] = Field(
        None, description="List of heatmap region dicts from POST /scan/heatmap. "
        "Each dict must have: confidence, reason"
    )
    signature_result: Optional[dict] = Field(
        None, description="Response dict from POST /signature/verify. "
        "Must have: similarity_score, confidence, is_forgery"
    )
    compliance_result: Optional[dict] = Field(
        None, description="Response dict from POST /compliance/analyze. "
        "Must have: findings (list with compliance_severity), overall_compliance_risk"
    )
    anomaly_result: Optional[dict] = Field(
        None, description="Response dict from POST /anomaly/detect. "
        "Must have: fusion_score (0–1), fusion_severity, findings"
    )
    banking_result: Optional[dict] = Field(
        None, description="Banking authenticity analysis result. "
        "Must have: authenticity_score, confidence, findings (list of dicts with: finding, severity, risk_points, evidence, field)"
    )
    signature_intel_result: Optional[dict] = Field(
        None, description="Signature intelligence result from image-based analysis. "
        "Must have: has_signatures, signature_score, findings"
    )
    ocr_reliability: Optional[float] = Field(
        None, description="OCR reliability score 0–1 (1 = high confidence in extraction quality)"
    )
