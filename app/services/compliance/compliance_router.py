"""
Compliance Router — Routes compliance checks to the correct rule set
based on the source document type.

Routing:
- bank_statement → banking_compliance.py + aml_rules.py
- website / forensic → cyber_compliance.py + aml_rules.py
- upload → banking_compliance.py + aml_rules.py  (default for uploads)
"""
import re
import uuid
import structlog
from datetime import datetime
from typing import List, Dict, Optional

from app.models.compliance import (
    ComplianceFinding,
    ComplianceReport,
    ComplianceCheckRequest,
    ComplianceSeverity,
    Regulation,
    ComplianceAction,
)

from app.services.compliance.banking_compliance import BANKING_COMPLIANCE_RULES
from app.services.compliance.cyber_compliance import CYBER_COMPLIANCE_RULES
from app.services.compliance.aml_rules import AML_RULES

logger = structlog.get_logger(__name__)


CYBER_SOURCE_TYPES = {"forensic", "heatmap", "scan", "website", "domain"}
BANKING_SOURCE_TYPES = {"upload", "bank_statement"}


def _normalise(text: str) -> str:
    return text.lower().strip()


def _match_finding(finding: dict, rule: dict) -> bool:
    message = _normalise(finding.get("message", ""))
    category = _normalise(finding.get("category", ""))
    region_type = _normalise(finding.get("region_type", ""))
    reason = _normalise(finding.get("reason", ""))
    signal_origin = _normalise(finding.get("signal_origin", ""))
    source_type = _normalise(finding.get("source_type", ""))
    risk_level = _normalise(finding.get("risk", ""))
    risk_level = risk_level or _normalise(finding.get("severity", ""))
    reasons_list = [r.lower() for r in finding.get("reasons", [])]

    structural_text = f"{category} {region_type} {signal_origin} {source_type}"
    evidence_text = f"{message} {reason} {risk_level}"
    evidence_text += " " + " ".join(reasons_list)

    match_cats = [_normalise(c) for c in rule.get("match_categories", [])]
    match_kws = [_normalise(k) for k in rule.get("match_keywords", [])]
    exclude_cats = [_normalise(c) for c in rule.get("exclude_categories", [])]

    if exclude_cats and any(ec in structural_text for ec in exclude_cats):
        return False

    has_category = bool(category or region_type or signal_origin)
    cat_match = any(c in structural_text for c in match_cats) if match_cats else True
    kw_match = False
    if match_kws:
        for kw in match_kws:
            pattern = r'\b' + re.escape(kw) + r'\b'
            if re.search(pattern, evidence_text):
                kw_match = True
                break

    if match_cats and match_kws:
        return (cat_match or not has_category) and kw_match
    elif match_cats:
        return cat_match or not has_category
    elif match_kws:
        return kw_match
    return False


def _build_summary(finding_objs: List[ComplianceFinding]) -> dict:
    counts = {}
    severity_counts = {}
    for reg in Regulation:
        counts[reg.value] = 0
        severity_counts[reg.value] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    highest_sev = ComplianceSeverity.LOW
    severity_order = [ComplianceSeverity.LOW, ComplianceSeverity.MEDIUM,
                      ComplianceSeverity.HIGH, ComplianceSeverity.CRITICAL]

    for f in finding_objs:
        rv = f.regulation.value
        counts[rv] = counts.get(rv, 0) + 1
        sv = severity_counts.get(rv, {})
        sv[f.compliance_severity.value] = sv.get(f.compliance_severity.value, 0) + 1
        if severity_order.index(f.compliance_severity) > severity_order.index(highest_sev):
            highest_sev = f.compliance_severity

    return {
        "total_compliance_findings": len(finding_objs),
        "per_regulation": counts,
        "per_severity": {
            rv: dict(sorted(sev.items()))
            for rv, sev in severity_counts.items()
        },
        "overall_compliance_risk": highest_sev.value,
    }


def _select_rules(source_type: str) -> List[Dict]:
    """Select the appropriate rule set based on source type."""
    st = source_type.lower().strip()

    if st in CYBER_SOURCE_TYPES:
        logger.info("Compliance routing to CYBER rules", source_type=source_type)
        return CYBER_COMPLIANCE_RULES + AML_RULES

    if st in BANKING_SOURCE_TYPES:
        logger.info("Compliance routing to BANKING rules", source_type=source_type)
        return BANKING_COMPLIANCE_RULES + AML_RULES

    logger.warning("Compliance routing unknown source type, defaulting to ALL rules",
                   source_type=source_type)
    return BANKING_COMPLIANCE_RULES + CYBER_COMPLIANCE_RULES + AML_RULES


def analyze(request: ComplianceCheckRequest) -> ComplianceReport:
    """Route compliance analysis to the correct rule set."""
    logger.info("Compliance analysis started", source=request.source_type,
                finding_count=len(request.findings))

    rules = _select_rules(request.source_type)

    compliance_findings: List[ComplianceFinding] = []
    seen_signatures = set()

    for finding in request.findings:
        for rule in rules:
            if _match_finding(finding, rule):
                sig = (rule["regulation"].value, rule["reference"],
                       rule.get("severity", ComplianceSeverity.MEDIUM).value,
                       rule.get("match_keywords", [""])[0])
                if sig in seen_signatures:
                    continue
                seen_signatures.add(sig)

                compliance_findings.append(ComplianceFinding(
                    regulation=rule["regulation"],
                    reference=rule["reference"],
                    finding_type=finding.get("category") or finding.get("region_type", "unknown"),
                    finding_description=(
                        finding.get("message")
                        or finding.get("reason")
                        or (finding.get("reasons", [])[0] if finding.get("reasons") else "")
                    ),
                    risk_impact=rule["risk_impact"],
                    required_action=ComplianceAction(
                        action=rule["action"],
                        timeline=rule["timeline"],
                        responsible_party=rule["responsible_party"],
                    ),
                    compliance_severity=rule["severity"],
                    source_signal=finding.get("signal_origin") or finding.get("region_type", ""),
                ))

    report_id = f"comp-{uuid.uuid4().hex[:12]}"
    now = datetime.utcnow()
    summary = _build_summary(compliance_findings)

    logger.info("Compliance analysis complete", report_id=report_id,
                findings=len(compliance_findings), risk=summary["overall_compliance_risk"])

    return ComplianceReport(
        report_id=report_id,
        timestamp=now,
        source_type=request.source_type,
        source_id=request.source_id,
        findings=compliance_findings,
        summary=summary,
        overall_compliance_risk=summary["overall_compliance_risk"],
    )
