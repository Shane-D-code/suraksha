"""
AML Rules — Shared across banking and cyber compliance pipelines.

Contains AML-specific constants and rule definitions that apply
regardless of document type (bank statement or website).
"""
from app.models.compliance import Regulation, ComplianceSeverity


HIGH_RISK_JURISDICTIONS = [
    "CAYMAN ISLANDS",
    "PANAMA",
    "SEYCHELLES",
    "BELIZE",
    "BRITISH VIRGIN ISLANDS",
    "VANUATU",
]


AML_RULES = [
    # ── Offshore Jurisdiction Detection ─────────────────────────────
    {
        "regulation": Regulation.AML,
        "match_keywords": [j.lower() for j in HIGH_RISK_JURISDICTIONS],
        "reference": "PMLA 2002, Section 12(1)(b); FATF High-Risk Jurisdictions List",
        "risk_impact": "Transfer to a high-risk offshore jurisdiction may involve layering or "
                       "legitimisation of proceeds of crime — mandatory STR filing with FIU-IND",
        "action": "Investigate source of funds, verify beneficial ownership, "
                   "file Suspicious Transaction Report with FIU-IND within 7 days",
        "timeline": "Enhanced due diligence within 24 hours; STR within 7 days",
        "severity": ComplianceSeverity.CRITICAL,
        "responsible_party": "Money Laundering Reporting Officer",
    },
    # ── Large Cash Deposit Monitoring ───────────────────────────────
    {
        "regulation": Regulation.AML,
        "match_keywords": ["large cash deposit", "multiple large cash deposits",
                          "cash deposit threshold", "cash deposit detected"],
        "reference": "PMLA 2002, Section 12(1)(b); RBI AML Guidelines on Cash Transaction Reporting",
        "risk_impact": "Cash deposits exceeding regulatory threshold may indicate "
                       "structuring or layering of proceeds of crime — mandatory STR with FIU-IND",
        "action": "Verify source of funds, file Cash Transaction Report (CTR), "
                   "assess customer risk categorisation, file STR if unexplained",
        "timeline": "CTR filing within 7 days; enhanced due diligence within 24 hours",
        "severity": ComplianceSeverity.HIGH,
        "responsible_party": "Money Laundering Reporting Officer",
    },
]
