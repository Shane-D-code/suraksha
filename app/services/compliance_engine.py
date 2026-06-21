"""
Compliance Intelligence Engine (Facade).

Routes compliance checks to the appropriate rule set via compliance_router.
The original monolithic module is preserved as a facade for backward
compatibility — all existing imports continue to work.

Rule definitions have been split into:
  - app/services/compliance/banking_compliance.py   → bank statements, KYC, AML
  - app/services/compliance/cyber_compliance.py     → websites, domains, phishing
  - app/services/compliance/aml_rules.py             → shared AML rules (offshore, cash)
"""
from app.models.compliance import ComplianceCheckRequest, ComplianceReport
from app.services.compliance.compliance_router import analyze as _router_analyze

HIGH_RISK_JURISDICTIONS = [
    "CAYMAN ISLANDS",
    "PANAMA",
    "SEYCHELLES",
    "BELIZE",
    "BRITISH VIRGIN ISLANDS",
    "VANUATU",
]


def analyze(request: ComplianceCheckRequest) -> ComplianceReport:
    """Route compliance analysis to the correct rule set."""
    return _router_analyze(request)
