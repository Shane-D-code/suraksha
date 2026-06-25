"""
Evidence Tree builder.

Groups flat findings into a hierarchical tree for the frontend.
Pure visualization — never removes or alters existing findings.
"""
import structlog
from typing import Any, Dict, List, Optional

logger = structlog.get_logger(__name__)

FIELD_CHECK_NAMES = {
    "account_number": "Account Number",
    "ifsc": "IFSC Code",
    "branch": "Branch Name",
    "bank_name": "Bank Name",
    "customer_name": "Customer Name",
    "holder_name": "Holder Name",
}


def _check_finding(field_key: str, findings: List[Dict[str, Any]]) -> Optional[Dict[str, str]]:
    """Check if a field is mentioned in findings (as a failure)."""
    key_lower = field_key.lower().replace("_", " ")
    for f in findings:
        finding_lower = (f.get("finding") or "").lower()
        field_val = (f.get("field") or "").lower()
        if key_lower in finding_lower or key_lower in field_val:
            return {
                "name": FIELD_CHECK_NAMES.get(field_key, field_key.replace("_", " ").title()),
                "status": "FAIL",
                "detail": f.get("finding", "Missing"),
            }
    return None


def _build_document_authenticity(
    banking_result: Optional[Dict[str, Any]],
    banking_findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build the Document Authenticity subtree."""
    checks: List[Dict[str, Any]] = []
    bank_name = (banking_result or {}).get("bank_name")

    # Bank Name check
    if bank_name:
        checks.append({"name": "Bank Name", "status": "PASS", "detail": bank_name.title()})
    else:
        checks.append({"name": "Bank Name", "status": "FAIL", "detail": "Not detected"})

    # Required field checks (account_number, ifsc, branch, etc.)
    for field_key in ("account_number", "ifsc", "branch", "customer_name", "holder_name"):
        fail = _check_finding(field_key, banking_findings)
        if fail:
            checks.append(fail)
        else:
            checks.append({"name": FIELD_CHECK_NAMES[field_key], "status": "PASS", "detail": "Present"})

    # Currency check
    currency_issues = [f for f in banking_findings if f.get("field") == "currency_consistency"]
    if currency_issues:
        details = currency_issues[0].get("evidence", currency_issues[0].get("finding", "Non-INR detected"))
        checks.append({"name": "Currency", "status": "FAIL", "detail": str(details)[:80]})
    else:
        checks.append({"name": "Currency", "status": "PASS", "detail": "INR"})

    overall = "FAIL" if any(c["status"] == "FAIL" for c in checks) else "PASS"
    return {"label": "Document Authenticity", "status": overall, "checks": checks}


def _build_financial_integrity(
    banking_result: Optional[Dict[str, Any]],
    banking_findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build the Financial Integrity subtree."""
    br = banking_result or {}
    checks: List[Dict[str, Any]] = []

    # Balance fields
    balance_fields = [
        ("opening_balance", "Opening Balance"),
        ("total_credits", "Credits"),
        ("total_debits", "Debits"),
        ("closing_balance", "Closing Balance"),
    ]
    for key, label in balance_fields:
        val = br.get(key)
        if val is not None:
            checks.append({"name": label, "status": "PASS", "detail": f"₹{val:,.2f}"})
        else:
            checks.append({"name": label, "status": "N/A", "detail": "Not available"})

    # Balance reconciliation
    has_recon_issue = br.get("has_balance_reconciliation_issue", False)
    balance_valid = br.get("balance_valid")
    if has_recon_issue:
        checks.append({"name": "Balance Reconciliation", "status": "FAIL", "detail": "Mismatch detected"})
    elif balance_valid is True:
        checks.append({"name": "Balance Reconciliation", "status": "PASS", "detail": "Verified"})
    else:
        checks.append({"name": "Balance Reconciliation", "status": "N/A", "detail": "Not checked"})

    # Transaction total
    has_txn_mismatch = br.get("has_transaction_total_mismatch", False)
    txn_count = br.get("transaction_count", 0)
    if has_txn_mismatch:
        checks.append({"name": "Transaction Totals", "status": "FAIL", "detail": "Mismatch detected"})
    elif txn_count > 0:
        checks.append({"name": "Transaction Totals", "status": "PASS", "detail": f"{txn_count} transactions"})
    else:
        checks.append({"name": "Transaction Totals", "status": "N/A", "detail": "No transactions"})

    # Running balance
    has_running_issue = br.get("has_running_balance_issue", False)
    if has_running_issue:
        checks.append({"name": "Running Balance", "status": "FAIL", "detail": "Discrepancy detected"})
    elif balance_valid is True and txn_count >= 3:
        checks.append({"name": "Running Balance", "status": "PASS", "detail": "Verified"})
    else:
        checks.append({"name": "Running Balance", "status": "N/A", "detail": "Not checked"})

    overall = "FAIL" if any(c["status"] == "FAIL" for c in checks) else "PASS"
    return {"label": "Financial Integrity", "status": overall, "checks": checks}


def _build_compliance_tree(
    compliance_findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build the AML & Compliance subtree."""
    checks: List[Dict[str, Any]] = []
    for f in compliance_findings:
        reg = f.get("regulation", "Compliance")
        desc = f.get("finding_description", "Finding")
        sev = f.get("compliance_severity", "MEDIUM")
        status = "FAIL" if sev in ("HIGH", "CRITICAL") else "WARN" if sev == "MEDIUM" else "PASS"
        checks.append({
            "name": reg,
            "status": status,
            "detail": desc[:120],
        })

    overall = "FAIL" if any(c["status"] == "FAIL" for c in checks) else "PASS" if checks else "N/A"
    return {"label": "AML & Compliance", "status": overall, "checks": checks}


def _build_metadata_tree(xai_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the Document Metadata subtree."""
    checks: List[Dict[str, Any]] = []
    for f in xai_findings:
        ft = f.get("finding_type", "unknown").replace("_", " ").title()
        desc = f.get("plain_english", f.get("description", ""))
        sev = f.get("severity", "LOW")
        status = "FAIL" if sev in ("HIGH", "CRITICAL") else "WARN" if sev == "MEDIUM" else "PASS"
        checks.append({
            "name": ft,
            "status": status,
            "detail": desc[:100] or ft,
        })

    overall = "FAIL" if any(c["status"] == "FAIL" for c in checks) else "PASS" if checks else "N/A"
    return {"label": "Document Metadata", "status": overall, "checks": checks}


def _build_anomaly_tree(anomaly_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the Anomaly Detection subtree."""
    checks: List[Dict[str, Any]] = []
    for f in anomaly_findings:
        method = f.get("method", "analysis").replace("_", " ").title()
        desc = f.get("explanation", f.get("finding", ""))
        sev = f.get("severity", "LOW")
        status = "FAIL" if sev in ("HIGH", "CRITICAL") else "WARN" if sev == "MEDIUM" else "PASS"
        checks.append({
            "name": method,
            "status": status,
            "detail": desc[:100] or method,
        })

    overall = "FAIL" if any(c["status"] == "FAIL" for c in checks) else "PASS" if checks else "PASS"
    return {"label": "Anomaly Detection", "status": overall, "checks": checks}


def build_evidence_tree(
    banking_result: Optional[Dict[str, Any]] = None,
    banking_findings: Optional[List[Dict[str, Any]]] = None,
    compliance_findings: Optional[List[Dict[str, Any]]] = None,
    xai_findings: Optional[List[Dict[str, Any]]] = None,
    anomaly_findings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Build a hierarchical evidence tree grouping findings by category.

    Returns nested JSON with label, status, and checks arrays.
    Frontend-only consumption — never removes existing flat findings.
    """
    banking_findings = banking_findings or []
    compliance_findings = compliance_findings or []
    xai_findings = xai_findings or []
    anomaly_findings = anomaly_findings or []

    categories: List[Dict[str, Any]] = []

    # Document Authenticity
    doc_auth = _build_document_authenticity(banking_result, banking_findings)
    categories.append(doc_auth)

    # Financial Integrity
    fin_int = _build_financial_integrity(banking_result, banking_findings)
    categories.append(fin_int)

    # AML & Compliance
    comp = _build_compliance_tree(compliance_findings)
    if comp.get("checks"):
        categories.append(comp)

    # Document Metadata
    meta = _build_metadata_tree(xai_findings)
    if meta.get("checks"):
        categories.append(meta)

    # Anomaly Detection
    anomaly = _build_anomaly_tree(anomaly_findings)
    if anomaly.get("checks"):
        categories.append(anomaly)

    tree = {"categories": categories}

    # Overall pass/fail summary
    all_fail = any(c["status"] == "FAIL" for c in categories)
    tree["overall"] = "FAIL" if all_fail else "PASS"

    logger.info("Evidence tree built", categories=len(categories))
    return tree
