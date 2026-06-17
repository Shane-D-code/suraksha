"""
Compliance Intelligence Engine.

Maps detected anomalies from the forensic, heatmap, and scan pipelines to
regulatory requirements under:
- RBI KYC Guidelines (Master Direction DOR.AML.REC.58/14.01.001/2021-22)
- Anti-Money Laundering — PMLA 2002 & Rules
- Digital Personal Data Protection Act 2023
- CERT-In Directions No. 20(3)/2022-CERT-In

Each anomaly generates one or more ComplianceFinding objects with:
- Regulation reference (specific clause)
- Risk impact description
- Required action + timeline
- Compliance severity
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

logger = structlog.get_logger(__name__)


# ── Regulatory Keyword Mapping Tables ─────────────────────────────────

# Each entry maps pattern keywords found in a finding's message, category,
# region_type, or signal_origin to one or more compliance obligations.

COMPLIANCE_RULES: List[Dict] = [
    # ── RBI KYC Guidelines ──────────────────────────────────────────
    {
        "regulation": Regulation.RBI_KYC,
        "match_keywords": ["external_submission", "external domain", "data exfiltration",
                          "submits data to external"],
        "match_categories": ["Form Behavior"],
        "reference": "RBI Master Direction DOR.AML.REC.58/14.01.001/2021-22, Section 34",
        "risk_impact": "Unauthorised disclosure of KYC data; customer confidentiality breach "
                       "exposes reporting entity to regulatory action under KYC-AML framework",
        "action": "Investigate data exfiltration path, review vendor data-processing agreements, "
                  "and verify customer consent records",
        "timeline": "Immediate containment, report to board within 48 hours",
        "severity": ComplianceSeverity.CRITICAL,
        "responsible_party": "Chief Compliance Officer",
    },
    {
        "regulation": Regulation.RBI_KYC,
        "match_keywords": ["password in iframe", "password_in_iframe", "credential harvest",
                          "credential harvesting"],
        "match_categories": ["Form Behavior"],
        "reference": "RBI Master Direction on Cyber Resilience Framework, Section 7.2",
        "risk_impact": "Credential harvesting leads to account takeover and financial fraud — "
                       "direct violation of customer data protection obligations",
        "action": "Implement input-field security controls, conduct penetration testing of "
                  "login interfaces, and file cyber-incident report with RBI",
        "timeline": "Immediate remediation, regulatory notification within 6 hours",
        "severity": ComplianceSeverity.CRITICAL,
        "responsible_party": "CISO / Head of IT",
    },
    {
        "regulation": Regulation.RBI_KYC,
        "match_keywords": ["hidden input", "hidden_input", "hidden field", "hidden form"],
        "match_categories": ["Form Behavior"],
        "reference": "RBI Master Direction DOR.AML.REC.58/14.01.001/2021-22, Section 12",
        "risk_impact": "Covert data collection violates KYC data-collection norms — "
                       "customers must be informed of all data collected",
        "action": "Audit all form fields, remove unauthorised hidden fields, update privacy notice",
        "timeline": "Audit within 7 days, remediate within 30 days",
        "severity": ComplianceSeverity.HIGH,
        "responsible_party": "Data Protection Officer",
    },
    {
        "regulation": Regulation.RBI_KYC,
        "match_keywords": ["brand impersonation", "brand_impersonation", "Brand Impersonation",
                          "logo", "brand logo"],
        "match_categories": ["Brand Impersonation"],
        "reference": "RBI Master Direction on Digital Payment Security, Section 5",
        "risk_impact": "Brand impersonation undermines trust in digital banking channels "
                       "and may cause customer financial loss",
        "action": "Issue customer alert, file complaint with CERT-In, request domain takedown, "
                  "and notify affected customers",
        "timeline": "Customer alert within 24 hours, takedown within 72 hours",
        "severity": ComplianceSeverity.MEDIUM,
        "responsible_party": "Brand Protection Team",
    },
    {
        "regulation": Regulation.RBI_KYC,
        "match_keywords": ["script", "external script", "suspicious script", "script domain"],
        "match_categories": ["Script Analysis"],
        "reference": "RBI Master Direction on Cyber Resilience Framework, Section 4",
        "risk_impact": "Third-party scripts may exfiltrate KYC data without customer consent — "
                       "violates outsourcing guidelines",
        "action": "Audit all third-party scripts, implement Content Security Policy, review "
                  "vendor due-diligence reports",
        "timeline": "Script audit within 72 hours, CSP deployment within 2 weeks",
        "severity": ComplianceSeverity.HIGH,
        "responsible_party": "IT Security Team",
    },
    {
        "regulation": Regulation.RBI_KYC,
        "match_keywords": ["right_click", "right-click", "context menu"],
        "match_categories": ["DOM Manipulation"],
        "reference": "RBI Master Direction on Cyber Resilience Framework, Section 9",
        "risk_impact": "User-protection mechanism — limited direct KYC impact but indicates "
                       "evasion techniques may be present",
        "action": "Monitor for additional evasion techniques; ensure user awareness materials "
                  "are accessible",
        "timeline": "Monitor as part of ongoing compliance review",
        "severity": ComplianceSeverity.LOW,
        "responsible_party": "Compliance Monitoring Team",
    },
    # ── AML (PMLA 2002) ────────────────────────────────────────────
    {
        "regulation": Regulation.AML,
        "match_keywords": ["known malicious", "threat feed", "threat_feed", "malicious",
                          "blacklist", "known_malicious"],
        "match_categories": ["Domain Intelligence", "Infrastructure"],
        "reference": "PMLA 2002, Section 12(1)(b); PML Rules, Rule 8(2)",
        "risk_impact": "Link to known financial-crime infrastructure — reporting entity must "
                       "file Suspicious Transaction Report with FIU-IND",
        "action": "Immediately file STR with FIU-IND, assess customer risk categorisation, "
                  "consider filing freezing order under PMLA Section 5",
        "timeline": "STR filing within 7 days of detection; freeze assessment within 24 hours",
        "severity": ComplianceSeverity.CRITICAL,
        "responsible_party": "Money Laundering Reporting Officer",
    },
    {
        "regulation": Regulation.AML,
        "match_keywords": ["campaign", "campaign_id", "active campaign", "phishing campaign",
                          "campaign participation"],
        "match_categories": ["Infrastructure", "Domain Intelligence"],
        "reference": "PMLA 2002, Section 12(1A); PML Rules, Rule 7(3)",
        "risk_impact": "Domain is part of an organised fraud network — potential money-laundering "
                       "typology requiring inter-agency coordination",
        "action": "File STR with FIU-IND, enhance monitoring for related transactions, "
                  "coordinate with law enforcement agencies",
        "timeline": "Enhanced monitoring within 24 hours; STR within 7 days",
        "severity": ComplianceSeverity.CRITICAL,
        "responsible_party": "Compliance Officer / MLRO",
    },
    {
        "regulation": Regulation.AML,
        "match_keywords": ["domain age", "domain_age", "new domain", "recent registration",
                          "days old"],
        "match_categories": ["Domain Intelligence"],
        "reference": "PMLA 2002, Rule 7(3); RBI Master Direction on KYC, Section 34",
        "risk_impact": "Newly registered domain used for financial services — indicates "
                       "possible shell entity or high-risk customer activity",
        "action": "Perform enhanced KYC due diligence, verify beneficial ownership "
                  "and source of funds",
        "timeline": "Enhanced due diligence within 7 days",
        "severity": ComplianceSeverity.HIGH,
        "responsible_party": "KYC Review Team",
    },
    {
        "regulation": Regulation.AML,
        "match_keywords": ["gnn", "gnn_similarity", "similarity", "graph_score",
                          "infrastructure similarity"],
        "match_categories": ["Infrastructure"],
        "reference": "PMLA 2002, Rule 8(2); PML Rules, Rule 2(d)",
        "risk_impact": "Infrastructure pattern matches known money-laundering typology — "
                       "requires investigation and possible STR filing",
        "action": "Investigate typology match, review transaction patterns of related customers, "
                  "file STR if proceeds of crime suspected",
        "timeline": "Investigation within 14 days; STR within 7 days of suspicion",
        "severity": ComplianceSeverity.HIGH,
        "responsible_party": "Investigation Team / MLRO",
    },
    {
        "regulation": Regulation.AML,
        "match_keywords": ["social engineering", "urgency", "urgent", "social_engineering"],
        "match_categories": ["Content"],
        "reference": "PMLA 2002, Section 12(1)(c); RBI AML Guidelines, Annex II",
        "risk_impact": "Social-engineering content may be used for financial fraud — "
                       "customers may be tricked into authorising transactions",
        "action": "Issue customer awareness notification, monitor for related fraud attempts, "
                  "file STR if financial loss suspected",
        "timeline": "Customer notification within 48 hours",
        "severity": ComplianceSeverity.MEDIUM,
        "responsible_party": "Customer Protection Team",
    },
    {
        "regulation": Regulation.AML,
        "match_keywords": ["invalid ssl", "ssl", "ssl_valid", "ssl certificate", "no ssl"],
        "match_categories": ["Domain Intelligence"],
        "reference": "PMLA 2002, Rule 7(2); RBI KYC Master Direction Section 19",
        "risk_impact": "Weak or missing TLS indicates poor KYC infrastructure — "
                       "impersonation risk for financial institutions",
        "action": "Verify customer domain uses valid TLS; review risk categorisation",
        "timeline": "Review within 30 days",
        "severity": ComplianceSeverity.MEDIUM,
        "responsible_party": "IT Operations",
    },
    # ── DPDP Act 2023 ───────────────────────────────────────────────
    {
        "regulation": Regulation.DPDP,
        "match_keywords": ["external_submission", "external domain", "data exfiltration",
                          "submits data to external"],
        "match_categories": ["Form Behavior"],
        "reference": "DPDP Act 2023, Section 8(1) read with Section 17",
        "risk_impact": "Cross-border or third-party data transfer without explicit consent — "
                       "violates data-fiduciary obligations under DPDP Act",
        "action": "Obtain valid consent with notice, review cross-border data-transfer "
                  "agreements, register as significant data fiduciary if applicable",
        "timeline": "Consent remediation within 30 days; report breach to Board within 72 hours",
        "severity": ComplianceSeverity.CRITICAL,
        "responsible_party": "Data Protection Officer",
    },
    {
        "regulation": Regulation.DPDP,
        "match_keywords": ["password in iframe", "password_in_iframe", "credential harvest",
                          "credential harvesting"],
        "match_categories": ["Form Behavior"],
        "reference": "DPDP Act 2023, Section 9(1); Section 16(1)",
        "risk_impact": "Personal data breach involving passwords — mandatory notification "
                       "to Data Protection Board under Section 16",
        "action": "Notify affected data principals, report breach to Data Protection Board, "
                  "implement technical safeguards for credential collection",
        "timeline": "Breach notification within 72 hours; principal notification without delay",
        "severity": ComplianceSeverity.CRITICAL,
        "responsible_party": "Data Protection Officer / CISO",
    },
    {
        "regulation": Regulation.DPDP,
        "match_keywords": ["hidden input", "hidden_input", "hidden field", "hidden form"],
        "match_categories": ["Form Behavior"],
        "reference": "DPDP Act 2023, Section 5(1)(c); Section 8(1)",
        "risk_impact": "Covert data processing without notice violates data-minimisation "
                       "principle and consent requirements",
        "action": "Disclose all data-collection points, implement purpose limitation, "
                  "obtain fresh consent for any non-essential data",
        "timeline": "Disclosure update within 14 days; consent remediation within 45 days",
        "severity": ComplianceSeverity.HIGH,
        "responsible_party": "Data Protection Officer",
    },
    {
        "regulation": Regulation.DPDP,
        "match_keywords": ["script", "external script", "suspicious script", "script domain",
                          "external_script"],
        "match_categories": ["Script Analysis"],
        "reference": "DPDP Act 2023, Section 8(3); Section 9(3)",
        "risk_impact": "Third-party scripts process personal data without notice or consent — "
                       "violates data-processor obligations",
        "action": "Update privacy notice with all data-processor details, review processor "
                  "agreements for DPDP compliance, audit data flows",
        "timeline": "Processor audit within 30 days; notice update within 14 days",
        "severity": ComplianceSeverity.HIGH,
        "responsible_party": "Data Protection Officer",
    },
    {
        "regulation": Regulation.DPDP,
        "match_keywords": ["brand impersonation", "brand_impersonation", "Brand Impersonation",
                          "logo"],
        "match_categories": ["Brand Impersonation"],
        "reference": "DPDP Act 2023, Section 6(1); Section 7(1)",
        "risk_impact": "Misleading representation may trick data principals into providing "
                       "consent under false pretences — consent is not valid",
        "action": "Issue public notice, request impersonating site takedown, review consent "
                  "mechanisms for validity",
        "timeline": "Public notice within 24 hours; takedown within 72 hours",
        "severity": ComplianceSeverity.MEDIUM,
        "responsible_party": "Legal / DPO",
    },
    {
        "regulation": Regulation.DPDP,
        "match_keywords": ["right_click", "right-click", "context menu"],
        "match_categories": ["DOM Manipulation"],
        "reference": "DPDP Act 2023, Section 13(1)",
        "risk_impact": "Restricted user rights may hinder data principals from exercising "
                       "their rights — limited direct DPDP impact",
        "action": "Ensure data principals retain ability to access their rights; "
                  "enable standard browser controls where feasible",
        "timeline": "Review within 90 days",
        "severity": ComplianceSeverity.LOW,
        "responsible_party": "Product Team",
    },
    # ── CERT-In Directions ──────────────────────────────────────────
    {
        "regulation": Regulation.CERT_IN,
        "match_keywords": ["password in iframe", "password_in_iframe", "credential harvest",
                          "credential harvesting", "credential theft"],
        "match_categories": ["Form Behavior"],
        "reference": "CERT-In Direction No. 20(3)/2022-CERT-In, Clause 4(a)",
        "risk_impact": "Credential-theft incident — mandatory reporting category under "
                       "CERT-In directions for cybersecurity incidents",
        "action": "Report incident to CERT-In with all indicators of compromise; preserve "
                  "logs for minimum 180 days as per Clause 8; conduct forensic analysis",
        "timeline": "Report to CERT-In within 6 hours of detection",
        "severity": ComplianceSeverity.CRITICAL,
        "responsible_party": "CISO / Incident Response Team",
    },
    {
        "regulation": Regulation.CERT_IN,
        "match_keywords": ["known malicious", "threat feed", "threat_feed", "malicious",
                          "blacklist", "known_malicious", "targeted attack"],
        "match_categories": ["Domain Intelligence"],
        "reference": "CERT-In Direction No. 20(3)/2022-CERT-In, Clause 4(vii)",
        "risk_impact": "Targeted or targeted-attack incident involving known malicious "
                       "infrastructure — mandatory reporting",
        "action": "Report incident to CERT-In with IP addresses, domains, and TLS hashes; "
                  "coordinate with CERT-In for mitigation",
        "timeline": "Report to CERT-In within 6 hours of detection",
        "severity": ComplianceSeverity.CRITICAL,
        "responsible_party": "Incident Response Team",
    },
    {
        "regulation": Regulation.CERT_IN,
        "match_keywords": ["campaign", "campaign_id", "active campaign", "phishing campaign",
                          "campaign participation"],
        "match_categories": ["Infrastructure"],
        "reference": "CERT-In Direction No. 20(3)/2022-CERT-In, Clause 4(x)",
        "risk_impact": "Multi-organisation attack campaign detected — requires threat-intelligence "
                       "sharing with CERT-In",
        "action": "Share threat intelligence (indicators of compromise, TTPs) with CERT-In; "
                  "coordinate with MeitY for sector-wide alert",
        "timeline": "Initial report within 24 hours; full intelligence within 7 days",
        "severity": ComplianceSeverity.HIGH,
        "responsible_party": "Threat Intelligence Team",
    },
    {
        "regulation": Regulation.CERT_IN,
        "match_keywords": ["external_submission", "external domain", "data exfiltration",
                          "submits data to external"],
        "match_categories": ["Form Behavior"],
        "reference": "CERT-In Direction No. 20(3)/2022-CERT-In, Clause 4(b)",
        "risk_impact": "Data exfiltration incident — mandatory reporting category under "
                       "CERT-In directions",
        "action": "Report data-exfiltration incident to CERT-In; preserve forensic images "
                  "and logs for 180 days; notify affected data principals",
        "timeline": "Report to CERT-In within 6 hours of detection",
        "severity": ComplianceSeverity.CRITICAL,
        "responsible_party": "CISO / DPO",
    },
    {
        "regulation": Regulation.CERT_IN,
        "match_keywords": ["script", "external script", "suspicious script", "script domain",
                          "malware", "compromise"],
        "match_categories": ["Script Analysis"],
        "reference": "CERT-In Direction No. 20(3)/2022-CERT-In, Clause 4(e)",
        "risk_impact": "Website compromise or malware deployment through scripts — "
                       "mandatory reporting category",
        "action": "Conduct forensic investigation, report to CERT-In with malware samples, "
                  "implement web-application firewall rules",
        "timeline": "Report to CERT-In within 6 hours; forensic report within 14 days",
        "severity": ComplianceSeverity.HIGH,
        "responsible_party": "Incident Response Team",
    },
    {
        "regulation": Regulation.CERT_IN,
        "match_keywords": ["phishing landing", "credential harvest",
                          "submits data to external"],
        "match_categories": ["Form Behavior", "Domain Intelligence", "Infrastructure"],
        "reference": "CERT-In Direction No. 20(3)/2022-CERT-In, Clause 8; Clause 12",
        "risk_impact": "Phishing landing page targeting Indian citizens — CERT-In coordinates "
                       "with MeitY and service providers for takedown",
        "action": "File phishing report with CERT-In, request domain take-down from registrar, "
                  "preserve evidence for 180 days",
        "timeline": "CERT-In report within 24 hours; takedown within 72 hours",
        "severity": ComplianceSeverity.HIGH,
        "responsible_party": "Phishing Response Team",
    },
    {
        "regulation": Regulation.CERT_IN,
        "match_keywords": ["brand impersonation", "brand_impersonation", "Brand Impersonation",
                          "logo"],
        "match_categories": ["Brand Impersonation"],
        "reference": "CERT-In Direction No. 20(3)/2022-CERT-In, Clause 4(vi)",
        "risk_impact": "Phishing attack against Indian financial brand — requires "
                       "coordination with CERT-In and brand owner",
        "action": "Report phishing site to CERT-In with brand-name details and hosting "
                  "provider information; issue customer advisory",
        "timeline": "Report within 24 hours; customer advisory within 48 hours",
        "severity": ComplianceSeverity.MEDIUM,
        "responsible_party": "Brand Protection Team",
    },
    {
        "regulation": Regulation.CERT_IN,
        "match_keywords": ["suspicious tld", "tld", "suspicious_url", "suspicious domain",
                          "suspicious URL", "unusual tld"],
        "match_categories": ["Domain Intelligence"],
        "match_categories": ["Domain Intelligence"],
        "reference": "CERT-In Direction No. 20(3)/2022-CERT-In, Clause 9",
        "risk_impact": "Suspicious domain or URL may indicate attack infrastructure "
                       "targeting Indian entities",
        "action": "Monitor domain activity, verify against threat intelligence feeds, "
                  "report to CERT-In if confirmed malicious",
        "timeline": "Monitoring ongoing; report within 7 days if confirmed",
        "severity": ComplianceSeverity.MEDIUM,
        "responsible_party": "Monitoring Team",
    },
    {
        "regulation": Regulation.CERT_IN,
        "match_keywords": ["gnn", "graph_score", "gnn_similarity", "infrastructure pattern"],
        "match_categories": ["Infrastructure"],
        "reference": "CERT-In Direction No. 20(3)/2022-CERT-In, Clause 4(xi)",
        "risk_impact": "Novel attack infrastructure pattern detected — may indicate "
                       "targeted campaign against Indian entities",
        "action": "Share pattern with CERT-In as threat intelligence; monitor for "
                  "related infrastructure; update defensive rules",
        "timeline": "Share intelligence within 7 days",
        "severity": ComplianceSeverity.MEDIUM,
        "responsible_party": "Threat Intelligence Team",
    },
    {
        "regulation": Regulation.CERT_IN,
        "match_keywords": ["right_click", "right-click", "context menu", "iframe", "dom_manipulation"],
        "match_categories": ["DOM Manipulation"],
        "reference": "CERT-In Direction No. 20(3)/2022-CERT-In, Clause 8 (log retention)",
        "risk_impact": "User-evasion techniques may indicate malicious page behaviour — "
                       "logs must be preserved if incident confirmed",
        "action": "Enable logging for all user-interaction events; preserve logs for "
                  "minimum 180 days as required by CERT-In",
        "timeline": "Log configuration within 30 days",
        "severity": ComplianceSeverity.LOW,
        "responsible_party": "IT Operations",
    },
    # ── Document Upload / Banking Document Compliance ────────────────
    {
        "regulation": Regulation.RBI_KYC,
        "match_keywords": ["record-keeping", "record keeping", "metadata cannot be traced"],
        "match_categories": ["Metadata", "Ocr"],
        "reference": "RBI Master Direction DOR.AML.REC.58/14.01.001/2021-22, Section 12 — Record Keeping",
        "risk_impact": "Documents without complete metadata may not satisfy record-keeping requirements for regulated documents.",
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
    {
        "regulation": Regulation.AML,
        "match_keywords": ["implausible value", "implausible_value", "financial value pattern",
                          "structuring", "layering", "smurfing",
                          "round-dollar structuring"],
        "match_categories": ["Numeric", "Anomaly Detection"],
        "reference": "PMLA 2002, Section 12(1)(b) read with Rule 8(2) — Suspicious Transaction Reporting",
        "risk_impact": "Implausible or patterned financial values may indicate structuring or layering — reporting entity must file STR with FIU-IND if suspicion arises",
        "action": "Verify declared amounts against independent sources, assess customer transaction profile, file STR if unexplained",
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
        "risk_impact": "Monetary values detected in document — expected content for financial statements. No AML concern by itself.",
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
        "risk_impact": "Consistently rounded values are a recognised money-laundering typology — may indicate fabricated documentation designed to evade detection",
        "action": "Cross-check against bank transaction records, verify source-of-funds documentation, consider enhanced monitoring",
        "timeline": "Verification within 7 days; enhanced monitoring for 90 days if confirmed",
        "severity": ComplianceSeverity.MEDIUM,
        "responsible_party": "Financial Analysis Team / MLRO",
    },
    {
        "regulation": Regulation.RBI_KYC,
        "match_keywords": ["document pattern deviation", "document structure anomaly",
                          "document composition anomaly", "unusual pattern detected",
                          "unusual numerical pattern"],
        "match_categories": ["Anomaly Detection"],
        "reference": "RBI Master Direction on KYC, Section 34 — Periodic updation and document verification",
        "risk_impact": "Document pattern deviation may indicate falsified or tampered records — KYC norms require reporting entity to verify document authenticity",
        "action": "Perform enhanced due diligence on the document, request additional verification documents, flag for manager review",
        "timeline": "Enhanced verification within 48 hours; manager review within 7 days",
        "severity": ComplianceSeverity.MEDIUM,
        "responsible_party": "KYC Review Team / Branch Manager",
    },
    {
        "regulation": Regulation.RBI_KYC,
        "match_keywords": ["borderline", "signature", "embedded image", "embedded_image",
                          "image may contain signature", "reference specimen"],
        "match_categories": ["Signature"],
        "reference": "RBI Master Direction on KYC, Section 19 — Customer due diligence and signature verification",
        "risk_impact": "Signature on document cannot be verified against reference specimen — KYC norms require positive verification of customer signatures for financial transactions",
        "action": "Request wet-ink or digitally signed copy, arrange in-person verification, or use alternate authentication methods",
        "timeline": "Verification attempt within 24 hours; escalate if unresolved within 5 business days",
        "severity": ComplianceSeverity.MEDIUM,
        "responsible_party": "Branch Operations / Customer Verification Team",
    },
    {
        "regulation": Regulation.DPDP,
        "match_keywords": ["file is unusually large", "unusually large", "large file", "file size"],
        "match_categories": ["Metadata"],
        "reference": "DPDP Act 2023, Section 8(1) — Data quality and storage limitation (informational reference)",
        "risk_impact": "Oversized files may contain more data than expected — file size alone is not a compliance violation but may warrant a quick check.",
        "action": "Confirm file contents match expected document type.",
        "timeline": "No specific timeline — informational only.",
        "severity": ComplianceSeverity.LOW,
        "responsible_party": "Data Protection Officer",
    },
]


# ── Helper ────────────────────────────────────────────────────────────

def _normalise(text: str) -> str:
    """Lowercase and strip for matching."""
    return text.lower().strip()


def _match_finding(finding: dict, rule: dict) -> bool:
    """Check if a single finding dict triggers a compliance rule.

    Matching is split into two domains to prevent false positives:
    - Categories are matched against structural fields (category, region_type, signal_origin)
    - Keywords are matched against evidence fields (message, reason, risk level, reasons list)
    This prevents a keyword like 'signature' from matching just because it appears
    in a structural field like signal_origin='xai.signature.borderline'.
    """
    message = _normalise(finding.get("message", ""))
    category = _normalise(finding.get("category", ""))
    region_type = _normalise(finding.get("region_type", ""))
    reason = _normalise(finding.get("reason", ""))
    signal_origin = _normalise(finding.get("signal_origin", ""))
    source_type = _normalise(finding.get("source_type", ""))
    risk_level = _normalise(finding.get("risk", ""))
    risk_level = risk_level or _normalise(finding.get("severity", ""))
    reasons_list = [r.lower() for r in finding.get("reasons", [])]

    # Structural fields — where categories should be matched
    structural_text = f"{category} {region_type} {signal_origin} {source_type}"
    # Evidence fields — where keywords should be matched
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


def _map_severity_to_mlro(finding_severity: str) -> ComplianceSeverity:
    """Map a finding's severity to the compliance severity for matching."""
    s = finding_severity.upper().strip()
    if s == "CRITICAL":
        return ComplianceSeverity.CRITICAL
    elif s == "HIGH":
        return ComplianceSeverity.HIGH
    elif s == "MEDIUM":
        return ComplianceSeverity.MEDIUM
    return ComplianceSeverity.LOW


def _build_summary(finding_objs: List[ComplianceFinding]) -> dict:
    """Aggregate compliance findings for the report summary."""
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


# ── Public API ────────────────────────────────────────────────────────

def analyze(request: ComplianceCheckRequest) -> ComplianceReport:
    """
    Run compliance analysis on a set of findings.

    Each finding dict is matched against the regulatory mapping tables.
    Matching findings produce one or more ComplianceFinding objects with
    regulation-specific details.

    The result is a ComplianceReport with per-finding compliance mappings
    and an aggregated summary.
    """
    logger.info("Compliance analysis started", source=request.source_type,
                finding_count=len(request.findings))

    compliance_findings: List[ComplianceFinding] = []
    seen_signatures = set()

    for finding in request.findings:
        for rule in COMPLIANCE_RULES:
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
