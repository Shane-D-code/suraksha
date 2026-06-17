"""
Pydantic schemas for the compliance intelligence engine.

Maps detected anomalies to:
- RBI KYC Guidelines
- AML requirements (PMLA 2002)
- DPDP Act 2023
- CERT-In Directions
"""
from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum
from datetime import datetime


class Regulation(str, Enum):
    RBI_KYC = "RBI KYC Guidelines"
    AML = "Anti-Money Laundering (PMLA 2002)"
    DPDP = "Digital Personal Data Protection Act 2023"
    CERT_IN = "CERT-In Directions"


class ComplianceSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ComplianceAction(BaseModel):
    action: str = Field(..., description="Required remediation action")
    timeline: str = Field(..., description="Reporting or remediation timeline")
    responsible_party: str = Field(default="", description="Entity responsible for action")


class ComplianceFinding(BaseModel):
    model_config = {"protected_namespaces": ()}

    regulation: Regulation = Field(..., description="Regulatory framework")
    reference: str = Field(..., description="Specific regulation clause or direction number")
    finding_type: str = Field(..., description="Category of anomaly that triggered this")
    finding_description: str = Field(..., description="Original anomaly or finding description")
    risk_impact: str = Field(..., description="What regulatory risk this poses")
    required_action: ComplianceAction = Field(..., description="Remediation steps required")
    compliance_severity: ComplianceSeverity = Field(..., description="Severity under this regulation")
    source_signal: str = Field(default="", description="Which signal origin or region type triggered this")


class ComplianceReport(BaseModel):
    report_id: str = Field(..., description="Unique compliance report identifier")
    timestamp: datetime = Field(..., description="Report generation time")
    source_type: str = Field(..., description="Source pipeline: forensic, heatmap, scan")
    source_id: Optional[str] = Field(None, description="Original scan or analysis ID")
    findings: List[ComplianceFinding] = Field(..., description="Compliance-relevant findings")
    summary: dict = Field(..., description="Aggregated counts per regulation and severity")
    overall_compliance_risk: str = Field(default="", description="Highest severity across all regulations")


class ComplianceCheckRequest(BaseModel):
    source_type: str = Field(..., description="Source: forensic, heatmap, or scan")
    source_id: Optional[str] = Field(None, description="Optional original ID for traceability")
    findings: List[dict] = Field(..., description="List of raw findings to evaluate for compliance")

    class Config:
        json_schema_extra = {
            "example": {
                "source_type": "forensic",
                "source_id": "scan-abc-123",
                "findings": [
                    {
                        "severity": "HIGH",
                        "category": "Form Behavior",
                        "message": "Login form submits data to external domain",
                        "signal_origin": "form_analysis.external_submission"
                    }
                ]
            }
        }
