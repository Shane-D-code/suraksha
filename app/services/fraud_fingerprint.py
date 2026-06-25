"""
Fraud Fingerprint — deterministic evidence encoding.

Same evidence always produces the same fingerprint.
No ML, no AI — pure deterministic encoding.
"""
import structlog
from typing import Any, Dict, List, Optional

logger = structlog.get_logger(__name__)

SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_TO_DIGIT = {0: "0", 1: "1", 2: "2", 3: "3", 4: "4"}


def _max_severity_digit(findings: List[Dict[str, Any]], severity_key: str = "severity") -> str:
    """Get the highest severity digit from a list of findings."""
    max_sev = max(
        (SEVERITY_RANK.get(f.get(severity_key, "NONE").upper(), 0) for f in findings),
        default=0,
    )
    return SEVERITY_TO_DIGIT.get(max_sev, "0")


def _count_digit(findings: List[Any]) -> str:
    """Encode finding count as a digit (0-9)."""
    n = len(findings)
    if n >= 9:
        return "9"
    return str(n)


def _ocr_digit(reliability: Optional[float]) -> str:
    """Encode OCR reliability as a digit."""
    if reliability is None:
        return "0"
    if reliability >= 0.9:
        return "0"
    if reliability >= 0.7:
        return "1"
    if reliability >= 0.5:
        return "2"
    return "3"


def build_fraud_fingerprint(
    banking_findings: Optional[List[Dict[str, Any]]] = None,
    compliance_findings: Optional[List[Dict[str, Any]]] = None,
    xai_findings: Optional[List[Dict[str, Any]]] = None,
    anomaly_findings: Optional[List[Dict[str, Any]]] = None,
    signature_findings: Optional[List[Any]] = None,
    fraud_patterns: Optional[List[Dict[str, Any]]] = None,
    ocr_reliability: Optional[float] = None,
    banking_result: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build a deterministic fraud fingerprint from all module outputs.

    Format: AUTH{d}-OCR{d}-META{d}-AML{d}-COMP{d}-FIN{d}-ANOM{d}-SIG{d}-PAT{d}

    Same inputs always produce the same fingerprint.
    """
    banking_findings = banking_findings or []
    compliance_findings = compliance_findings or []
    xai_findings = xai_findings or []
    anomaly_findings = anomaly_findings or []
    signature_findings = signature_findings or []
    fraud_patterns = fraud_patterns or []

    # AUTH: Banking Authenticity — max severity
    auth_digit = _max_severity_digit(banking_findings)

    # OCR: OCR reliability level
    ocr_digit = _ocr_digit(ocr_reliability)

    # META: XAI/document metadata — max severity
    meta_digit = _max_severity_digit(xai_findings)

    # AML: AML compliance findings — max compliance_severity
    aml_findings = [f for f in compliance_findings if "aml" in (f.get("regulation") or "").lower()]
    aml_digit = _max_severity_digit(aml_findings, severity_key="compliance_severity")

    # COMP: Other compliance findings
    comp_findings = [f for f in compliance_findings if "aml" not in (f.get("regulation") or "").lower()]
    comp_digit = _max_severity_digit(comp_findings, severity_key="compliance_severity")

    # FIN: Financial integrity findings
    fin_findings = [f for f in banking_findings if f.get("field") == "transaction_integrity"]
    fin_digit = _max_severity_digit(fin_findings)

    # ANOM: Anomaly detection
    anom_digit = _max_severity_digit(anomaly_findings)

    # SIG: Signature
    sig_digit = _count_digit(signature_findings)

    # PAT: Fraud patterns
    pat_digit = _count_digit(fraud_patterns)

    fingerprint = (
        f"AUTH{auth_digit}-OCR{ocr_digit}-META{meta_digit}"
        f"-AML{aml_digit}-COMP{comp_digit}-FIN{fin_digit}"
        f"-ANOM{anom_digit}-SIG{sig_digit}-PAT{pat_digit}"
    )

    logger.info("Fraud fingerprint generated", fingerprint=fingerprint)
    return fingerprint
