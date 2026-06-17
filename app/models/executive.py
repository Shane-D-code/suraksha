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
