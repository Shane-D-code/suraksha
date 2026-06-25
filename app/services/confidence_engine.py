"""
Confidence Engine.

Enriches every existing finding with:
  - confidence (0-100)
  - severity (LOW / MEDIUM / HIGH / CRITICAL)
  - evidence_strength (LOW / MEDIUM / HIGH)

Also attaches evidence weightings:
  - weight (0-100)
  - source (which pipeline produced it)

Does NOT modify existing scores.
"""
import structlog
from typing import Any, Dict, List, Optional

logger = structlog.get_logger(__name__)

SEVERITY_WEIGHT_MAP = {
    "CRITICAL": {"weight": 25, "evidence_strength": "HIGH"},
    "HIGH": {"weight": 18, "evidence_strength": "HIGH"},
    "MEDIUM": {"weight": 10, "evidence_strength": "MEDIUM"},
    "LOW": {"weight": 3, "evidence_strength": "LOW"},
}

SOURCE_EVIDENCE_STRENGTH: Dict[str, str] = {
    "banking_authenticity": "HIGH",
    "financial_integrity": "HIGH",
    "compliance": "MEDIUM",
    "anomaly": "MEDIUM",
    "xai": "MEDIUM",
    "signature": "MEDIUM",
    "metadata": "LOW",
    "ocr": "LOW",
}


def enrich_findings(
    banking_findings: Optional[List[Dict[str, Any]]] = None,
    compliance_findings: Optional[List[Dict[str, Any]]] = None,
    anomaly_findings: Optional[List[Dict[str, Any]]] = None,
    xai_findings: Optional[List[Dict[str, Any]]] = None,
    signature_findings: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Enrich all findings with confidence, severity, evidence_strength, weight, and source."""
    enriched: List[Dict[str, Any]] = []
    banking_findings = banking_findings or []
    compliance_findings = compliance_findings or []
    anomaly_findings = anomaly_findings or []
    xai_findings = xai_findings or []
    signature_findings = signature_findings or []

    for f in banking_findings:
        sev = f.get("severity", "MEDIUM").upper()
        meta = SEVERITY_WEIGHT_MAP.get(sev, SEVERITY_WEIGHT_MAP["MEDIUM"])
        enriched.append({
            "title": f.get("finding", ""),
            "confidence": round(f.get("confidence", 0.85) * 100),
            "severity": sev,
            "evidence_strength": SOURCE_EVIDENCE_STRENGTH.get("banking_authenticity", "MEDIUM"),
            "weight": meta["weight"],
            "source": "banking_authenticity",
        })

    for f in compliance_findings:
        sev = f.get("compliance_severity", "MEDIUM").upper()
        meta = SEVERITY_WEIGHT_MAP.get(sev, SEVERITY_WEIGHT_MAP["MEDIUM"])
        enriched.append({
            "title": f.get("finding_description", ""),
            "confidence": 85,
            "severity": sev,
            "evidence_strength": SOURCE_EVIDENCE_STRENGTH.get("compliance", "MEDIUM"),
            "weight": meta["weight"],
            "source": "compliance",
        })

    for f in anomaly_findings:
        sev = f.get("severity", "LOW").upper()
        meta = SEVERITY_WEIGHT_MAP.get(sev, SEVERITY_WEIGHT_MAP["LOW"])
        enriched.append({
            "title": f.get("explanation", ""),
            "confidence": round(f.get("confidence", 0.7) * 100),
            "severity": sev,
            "evidence_strength": SOURCE_EVIDENCE_STRENGTH.get("anomaly", "MEDIUM"),
            "weight": meta["weight"],
            "source": f"anomaly.{f.get('method', 'unknown')}",
        })

    for f in xai_findings:
        sev = f.get("severity", "LOW").upper()
        meta = SEVERITY_WEIGHT_MAP.get(sev, SEVERITY_WEIGHT_MAP["LOW"])
        enriched.append({
            "title": f.get("plain_english", f.get("finding_type", "")),
            "confidence": round(f.get("confidence", 0.7) * 100),
            "severity": sev,
            "evidence_strength": SOURCE_EVIDENCE_STRENGTH.get("xai", "MEDIUM"),
            "weight": meta["weight"],
            "source": "xai",
        })

    for f in signature_findings:
        sev = f.get("severity", "LOW").upper() if isinstance(f, dict) else "LOW"
        enriched.append({
            "title": f.get("text", str(f)) if isinstance(f, dict) else str(f),
            "confidence": round(f.get("confidence", 0.7) * 100) if isinstance(f, dict) else 70,
            "severity": sev,
            "evidence_strength": SOURCE_EVIDENCE_STRENGTH.get("signature", "MEDIUM"),
            "weight": SEVERITY_WEIGHT_MAP.get(sev, SEVERITY_WEIGHT_MAP["LOW"])["weight"],
            "source": "signature",
        })

    logger.info("Confidence engine enriched findings", count=len(enriched))
    return enriched
