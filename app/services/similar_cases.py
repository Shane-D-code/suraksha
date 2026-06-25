"""
Similar Investigations — deterministic similarity search.

Compares current case against historical cases stored in the database.
Uses risk signature, bank, missing fields, fraud category, and decision.
No AI, no ML — pure deterministic attribute matching.
"""
import structlog
from typing import Any, Dict, List, Optional, Set
from datetime import datetime

logger = structlog.get_logger(__name__)

RISK_BANDS = [
    (0, 19, "Very Low"),
    (20, 39, "Low"),
    (40, 59, "Moderate"),
    (60, 79, "High"),
    (80, 100, "Critical"),
]


def _risk_band(score: int) -> str:
    for lo, hi, label in RISK_BANDS:
        if lo <= score <= hi:
            return label
    return "Unknown"


def _missing_fields(banking_findings: List[Dict[str, Any]]) -> Set[str]:
    fields: Set[str] = set()
    for f in banking_findings:
        field = f.get("field", "")
        finding = (f.get("finding") or "").lower()
        if "missing" in finding or f.get("risk_points", 0) > 10:
            fields.add(field)
    return fields


def _common(a: Set[str], b: Set[str]) -> List[str]:
    return sorted(a & b)


def _different(a: Set[str], b: Set[str]) -> List[str]:
    return sorted(a ^ b)


def compute_similarity(
    current: Dict[str, Any],
    historical: Dict[str, Any],
) -> float:
    """
    Compute deterministic similarity between two cases (0.0 - 100.0).

    Attributes compared:
      - Risk band (25 pts)
      - Bank name match (20 pts)  
      - Missing fields overlap (25 pts)
      - Fraud category match (15 pts)
      - Decision match (15 pts)
    """
    score = 0.0

    # 1. Risk band (25 pts)
    cur_band = _risk_band(current.get("risk_score", 0))
    his_band = _risk_band(historical.get("risk_score", 0))
    if cur_band == his_band:
        score += 25.0

    # 2. Bank name (20 pts)
    cur_bank = (current.get("bank_name") or "").lower().strip()
    his_bank = (historical.get("bank_name") or "").lower().strip()
    if cur_bank and his_bank and cur_bank == his_bank:
        score += 20.0
    elif cur_bank and his_bank:
        score += 5.0  # partial - both have bank names but different

    # 3. Missing fields overlap (25 pts)
    cur_missing = _missing_fields(current.get("banking_findings", []))
    his_missing = _missing_fields(historical.get("banking_findings", []))
    if cur_missing or his_missing:
        intersection = cur_missing & his_missing
        union = cur_missing | his_missing
        if union:
            jaccard = len(intersection) / len(union)
            score += jaccard * 25.0
        else:
            score += 25.0  # both have no missing fields → match
    else:
        score += 25.0  # neither has missing fields → match

    # 4. Fraud category (15 pts)
    cur_cat = (current.get("fraud_category") or "").lower().strip()
    his_cat = (historical.get("fraud_category") or "").lower().strip()
    if cur_cat and his_cat and cur_cat == his_cat:
        score += 15.0
    elif not cur_cat and not his_cat:
        score += 15.0
    elif cur_cat and his_cat:
        score += 5.0  # partial

    # 5. Decision match (15 pts)
    cur_dec = (current.get("decision") or "").upper().strip()
    his_dec = (historical.get("decision") or "").upper().strip()
    if cur_dec and his_dec and cur_dec == his_dec:
        score += 15.0
    elif not cur_dec and not his_dec:
        score += 15.0

    return round(score, 1)


def _extract_case_from_meta(meta: Dict[str, Any], scan_id: str, created_at: datetime) -> Dict[str, Any]:
    """Extract a comparable case dict from a DB Scan meta JSON."""
    banking_findings = []
    fraud_category = ""
    bank_name = ""
    risk_score = 0
    decision = ""
    recommendations: List[str] = []

    # Read from the raw findings stored in meta
    stored_findings = meta.get("findings", [])
    for sf in stored_findings:
        cat = sf.get("category", "")
        if cat == "banking_authenticity":
            banking_findings.append({
                "field": cat,
                "finding": sf.get("finding", ""),
                "severity": sf.get("severity", "LOW"),
                "risk_points": sf.get("score_contribution", 0) if sf.get("score_contribution") else 0,
            })

    # Try reading fraud_categories if stored
    fraud_cats = meta.get("audit_trail", {}).get("decision_card", {})
    if isinstance(fraud_cats, dict):
        fraud_category = fraud_cats.get("fraud_type", "")

    # Try bank name from sources
    sources = meta.get("sources", [])
    for s in sources:
        if "bank" in s.lower() or "hdfc" in s.lower():
            bank_name = s
            break

    # Risk and decision from a stored result
    stored_result = meta.get("result", {})
    if stored_result:
        risk_score = stored_result.get("risk_score", 0)
        decision = stored_result.get("decision", "")

    recommendations = meta.get("recommendations", [])

    return {
        "scan_id": scan_id,
        "created_at": created_at.isoformat() if created_at else "",
        "risk_score": risk_score,
        "bank_name": bank_name,
        "decision": decision,
        "fraud_category": fraud_category,
        "missing_fields": _missing_fields(banking_findings),
        "findings": [f.get("finding", "") for f in banking_findings],
        "recommendations": recommendations,
        "banking_findings": banking_findings,
    }


def find_similar_cases(
    current_case: Dict[str, Any],
    historical_cases: List[Dict[str, Any]],
    top_k: int = 5,
    min_similarity: float = 10.0,
) -> List[Dict[str, Any]]:
    """
    Find top-k most similar historical cases using deterministic matching.

    Args:
        current_case: dict with risk_score, bank_name, banking_findings, fraud_category, decision
        historical_cases: list of cases from DB
        top_k: max results
        min_similarity: minimum similarity threshold (0-100)

    Returns:
        List of {similarity_pct, scan_id, date, bank, risk_score, decision,
                 common_findings, different_findings, recommendations}
    """
    if not historical_cases:
        return []

    scored = []
    for case in historical_cases:
        sim = compute_similarity(current_case, case)
        if sim >= min_similarity:
            cur_missing = _missing_fields(current_case.get("banking_findings", []))
            his_missing = _missing_fields(case.get("banking_findings", []))
            scored.append({
                "similarity_pct": sim,
                "scan_id": case.get("scan_id", ""),
                "date": case.get("created_at", ""),
                "bank": case.get("bank_name", "Unknown"),
                "risk_score": case.get("risk_score", 0),
                "decision": case.get("decision", "N/A"),
                "common_findings": _common(cur_missing, his_missing),
                "different_findings": _different(cur_missing, his_missing),
                "recommendations": case.get("recommendations", []),
            })

    scored.sort(key=lambda x: x["similarity_pct"], reverse=True)
    return scored[:top_k]


def build_current_case_profile(
    risk_score: int,
    decision: str,
    bank_name: Optional[str],
    banking_findings: Optional[List[Dict[str, Any]]],
    fraud_categories: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a comparable case profile for the current investigation."""
    fraud_category = ""
    if fraud_categories:
        fraud_category = fraud_categories.get("primary", "")

    return {
        "risk_score": risk_score,
        "decision": decision,
        "bank_name": bank_name or "",
        "banking_findings": banking_findings or [],
        "fraud_category": fraud_category,
    }
