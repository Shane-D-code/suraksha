"""
Cyber Compliance Rules — Website / Web Application / Domain analysis.

Applies when the source document is a website, domain, or web page.
Covers:
- Form Behaviour (credential harvesting, hidden inputs, data exfiltration)
- Script Analysis (malicious / external scripts)
- Domain Intelligence (threat feeds, domain age, SSL/TLS)
- Brand Impersonation (logo misuse, phishing brands)
- DOM Manipulation (right-click blocking, iframe injection)
- Infrastructure (campaigns, GNN graph patterns)
- Content (social engineering)
- CERT-In Directions for cyber incidents
- DPDP Act for web-based data processing
"""
from app.models.compliance import Regulation, ComplianceSeverity


CYBER_COMPLIANCE_RULES = [
    # ── RBI KYC — Form Behaviour ─────────────────────────────────────
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
    # ── AML — Domain Intelligence & Infrastructure ───────────────────
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
    # ── DPDP Act 2023 — Web / Cyber ──────────────────────────────────
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
    # ── CERT-In Directions — Cyber Incident Reporting ────────────────
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
]
