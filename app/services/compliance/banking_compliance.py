"""
Banking Compliance Rules — Document Upload / Bank Statement analysis.

Applies when the source document is a bank statement or uploaded financial document.
Covers:
- Document record-keeping (metadata, OCR traceability)
- AML transaction analysis (implausible values, structuring, rounding anomalies)
- Pattern deviation (document structure anomalies)
- Signature verification
- KYC status checks
- Large file metadata concerns
"""
from app.models.compliance import Regulation, ComplianceSeverity


BANKING_COMPLIANCE_RULES = [
    # ── Document Record-Keeping ───────────────────────────────────────
    {
        "regulation": Regulation.RBI_KYC,
        "match_keywords": ["record-keeping", "record keeping", "metadata cannot be traced"],
        "match_categories": ["Metadata", "Ocr"],
        "reference": "RBI Master Direction DOR.AML.REC.58/14.01.001/2021-22, Section 12 — Record Keeping",
        "risk_impact": "Documents without complete metadata may not satisfy record-keeping requirements "
                       "for regulated documents.",
        "action": "If the document requires full audit trail, request version with intact metadata.",
        "timeline": "As needed — informational only.",
        "severity": ComplianceSeverity.LOW,
        "responsible_party": "Compliance Officer",
    },
    {
        "regulation": Regulation.CERT_IN,
        "match_keywords": ["forensic traceability"],
        "match_categories": ["Metadata"],
        "reference": "CERT-In Direction No. 20(3)/2022-CERT-In, Clause 8 — Log retention (informational reference)",
        "risk_impact": "Documents without readable metadata have limited forensic traceability.",
        "action": "If document authenticity is critical, request original with intact metadata.",
        "timeline": "As needed — informational only.",
        "severity": ComplianceSeverity.LOW,
        "responsible_party": "Forensic Analysis Team",
    },
    # ── AML — Transaction Analysis ────────────────────────────────────
    {
        "regulation": Regulation.AML,
        "match_keywords": ["implausible value", "implausible_value", "financial value pattern",
                          "structuring", "layering", "smurfing",
                          "round-dollar structuring"],
        "match_categories": ["Numeric", "Anomaly Detection"],
        "reference": "PMLA 2002, Section 12(1)(b) read with Rule 8(2) — Suspicious Transaction Reporting",
        "risk_impact": "Implausible or patterned financial values may indicate structuring or layering — "
                       "reporting entity must file STR with FIU-IND if suspicion arises",
        "action": "Verify declared amounts against independent sources, assess customer transaction profile, "
                  "file STR if unexplained",
        "timeline": "Internal investigation within 72 hours; STR within 7 days of suspicion",
        "severity": ComplianceSeverity.HIGH,
        "responsible_party": "Money Laundering Reporting Officer / Financial Analysis Team",
    },
    {
        "regulation": Regulation.AML,
        "match_keywords": ["monetary value", "monetary values", "amount", "financial value",
                          "currency amount", "transaction amount"],
        "match_categories": ["Numeric"],
        "reference": "PMLA 2002, Section 12(1)(b) — Ongoing customer due diligence (informational reference)",
        "risk_impact": "Monetary values detected in document — expected content for financial statements. "
                       "No AML concern by itself.",
        "action": "No action required — routine financial data detected.",
        "timeline": "Not applicable — informational only.",
        "severity": ComplianceSeverity.LOW,
        "responsible_party": "N/A",
        "exclude_categories": ["Banking Authenticity"],
    },
    {
        "regulation": Regulation.AML,
        "match_keywords": ["rounding anomaly", "rounding_anomaly", "rounded value", "rounded to thousand",
                          "rounded to nearest"],
        "match_categories": ["Numeric"],
        "reference": "PMLA 2002, Rule 8(1); Financial Intelligence Unit — Typology circular on round-dollar structuring",
        "risk_impact": "Consistently rounded values are a recognised money-laundering typology — "
                       "may indicate fabricated documentation designed to evade detection",
        "action": "Cross-check against bank transaction records, verify source-of-funds documentation, "
                  "consider enhanced monitoring",
        "timeline": "Verification within 7 days; enhanced monitoring for 90 days if confirmed",
        "severity": ComplianceSeverity.MEDIUM,
        "responsible_party": "Financial Analysis Team / MLRO",
    },
    # ── Document Pattern Deviation ────────────────────────────────────
    {
        "regulation": Regulation.RBI_KYC,
        "match_keywords": ["document pattern deviation", "document structure anomaly",
                          "document composition anomaly", "unusual pattern detected",
                          "unusual numerical pattern"],
        "match_categories": ["Anomaly Detection"],
        "reference": "RBI Master Direction on KYC, Section 34 — Periodic updation and document verification",
        "risk_impact": "Document pattern deviation may indicate falsified or tampered records — "
                       "KYC norms require reporting entity to verify document authenticity",
        "action": "Perform enhanced due diligence on the document, request additional verification documents, "
                  "flag for manager review",
        "timeline": "Enhanced verification within 48 hours; manager review within 7 days",
        "severity": ComplianceSeverity.MEDIUM,
        "responsible_party": "KYC Review Team / Branch Manager",
    },
    # ── Signature Verification ────────────────────────────────────────
    {
        "regulation": Regulation.RBI_KYC,
        "match_keywords": ["borderline", "signature", "embedded image", "embedded_image",
                          "image may contain signature", "reference specimen"],
        "match_categories": ["Signature"],
        "reference": "RBI Master Direction on KYC, Section 19 — Customer due diligence and signature verification",
        "risk_impact": "Signature on document cannot be verified against reference specimen — "
                       "KYC norms require positive verification of customer signatures for financial transactions",
        "action": "Request wet-ink or digitally signed copy, arrange in-person verification, "
                  "or use alternate authentication methods",
        "timeline": "Verification attempt within 24 hours; escalate if unresolved within 5 business days",
        "severity": ComplianceSeverity.MEDIUM,
        "responsible_party": "Branch Operations / Customer Verification Team",
    },
    # ── File Metadata (DPDP) ──────────────────────────────────────────
    {
        "regulation": Regulation.DPDP,
        "match_keywords": ["file is unusually large", "unusually large", "large file", "file size"],
        "match_categories": ["Metadata"],
        "reference": "DPDP Act 2023, Section 8(1) — Data quality and storage limitation (informational reference)",
        "risk_impact": "Oversized files may contain more data than expected — file size alone is not a "
                       "compliance violation but may warrant a quick check.",
        "action": "Confirm file contents match expected document type.",
        "timeline": "No specific timeline — informational only.",
        "severity": ComplianceSeverity.LOW,
        "responsible_party": "Data Protection Officer",
    },
    # ── Pending KYC Status ────────────────────────────────────────────
    {
        "regulation": Regulation.RBI_KYC,
        "match_keywords": ["kyc status: pending", "kyc status pending",
                          "kyc verification incomplete"],
        "match_categories": ["Ocr"],
        "reference": "RBI Master Direction DOR.AML.REC.58/14.01.001/2021-22, Section 9 — KYC Updation",
        "risk_impact": "Pending KYC status indicates customer due-diligence obligations "
                       "have not been fulfilled — regulatory action may be required",
        "action": "Initiate KYC updation process, obtain required customer documentation, "
                  "and restrict high-risk transactions until KYC is complete",
        "timeline": "KYC verification within 7 days; transaction restriction if overdue",
        "severity": ComplianceSeverity.HIGH,
        "responsible_party": "KYC Review Team / Branch Manager",
    },
]
