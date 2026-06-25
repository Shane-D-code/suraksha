"""
Pydantic schemas for the executive fraud dashboard.
"""
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime


class RiskDistribution(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class TrendPoint(BaseModel):
    date: str = Field(..., description="Date in YYYY-MM-DD format")
    fraud: int = Field(default=0, description="Fraudulent scans detected")
    compliance: int = Field(default=0, description="Compliance alerts triggered")
    scans: int = Field(default=0, description="Total scans processed")


class RecentScanEntry(BaseModel):
    scan_id: str = Field(default="", description="Scan identifier")
    source: str = Field(default="", description="Domain, URL, or document path")
    risk: str = Field(default="LOW", description="Risk level")
    timestamp: Optional[str] = Field(None, description="ISO timestamp")
    fraud_type: str = Field(default="", description="Category of fraud detected")
    compliance_flags: List[str] = Field(default_factory=list)


class ExecutiveDashboardResponse(BaseModel):
    total_documents_scanned: int = 0
    fraud_detected: int = 0
    high_risk: int = 0
    medium_risk: int = 0
    low_risk: int = 0
    compliance_alerts: int = 0
    risk_distribution: RiskDistribution = Field(default_factory=RiskDistribution)
    trend_analysis: List[TrendPoint] = Field(default_factory=list)
    recent_scans: List[RecentScanEntry] = Field(default_factory=list)


class ExecutiveDecisionResponse(BaseModel):
    fraud_probability: Optional[float] = None
    risk_score: Optional[int] = None
    decision: Optional[str] = None
    confidence: Optional[float] = None
    compliance: Optional[str] = None
    regulatory_risk: Optional[str] = None
    primary_reason: Optional[str] = None
    recommendation: Optional[str] = None
    updated_at: Optional[str] = None


class DashboardStatisticsResponse(BaseModel):
    documents_scanned: int = 0
    fraud_detected: int = 0
    high_risk: int = 0
    compliance_alerts: int = 0
    average_risk: float = 0.0
    updated_at: Optional[str] = None


class AnalystDecisionRequest(BaseModel):
    decision: str  # APPROVED / MANUAL_REVIEW / REJECTED
    reviewer_notes: Optional[str] = None
    assigned_team: Optional[str] = None
    notify_compliance: bool = False
    require_branch_verification: bool = False
    escalate_manager: bool = False
    freeze_processing: bool = False


class AnalystDecisionResponse(BaseModel):
    scan_id: str = ""
    decision: Optional[str] = None
    reviewer_notes: Optional[str] = None
    assigned_team: Optional[str] = None
    reviewed_by: Optional[str] = None
    review_completed_at: Optional[str] = None
    review_status: Optional[str] = None
    notify_compliance: bool = False
    require_branch_verification: bool = False
    escalate_manager: bool = False
    freeze_processing: bool = False
    message: Optional[str] = None
