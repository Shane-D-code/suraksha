"""
Pydantic schemas for the real-time Compliance Operations Dashboard.
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime


class ComplianceFindingEntry(BaseModel):
    id: int = 0
    scan_id: str = ""
    document_name: str = ""
    regulation: str = ""
    reference: str = ""
    finding_type: str = ""
    finding_description: str = ""
    risk_impact: Optional[str] = None
    required_action: Optional[str] = None
    compliance_severity: str = "LOW"
    status: str = "OPEN"
    assigned_to: Optional[str] = None
    analyst_decision: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    resolved_at: Optional[str] = None


class FrameworkCount(BaseModel):
    label: str = ""
    key: str = ""
    count: int = 0


class ComplianceChartData(BaseModel):
    labels: List[str] = Field(default_factory=list)
    values: List[int] = Field(default_factory=list)


class ComplianceAnalytics(BaseModel):
    findings_by_framework: List[FrameworkCount] = Field(default_factory=list)
    findings_by_severity: List[FrameworkCount] = Field(default_factory=list)
    daily_trend: List[dict] = Field(default_factory=list)
    open_vs_closed: ComplianceChartData = Field(default_factory=ComplianceChartData)
    resolution_times: List[dict] = Field(default_factory=list)


class ComplianceDashboardResponse(BaseModel):
    total_alerts: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    open_findings: int = 0
    under_review: int = 0
    resolved_today: int = 0
    avg_resolution_hours: Optional[float] = None
    highest_priority_framework: Optional[str] = None
    frameworks: List[FrameworkCount] = Field(default_factory=list)
    recent_findings: List[ComplianceFindingEntry] = Field(default_factory=list)
    pending_reviews: int = 0
    closed_today: int = 0
    analytics: ComplianceAnalytics = Field(default_factory=ComplianceAnalytics)
    updated_at: Optional[str] = None
