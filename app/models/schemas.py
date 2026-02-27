"""
Pydantic schemas for API request/response models.
"""
from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Optional, Dict, List, Any
from datetime import datetime
from enum import Enum
import re
from urllib.parse import urlparse


class RiskLevel(str, Enum):
    """Risk level enumeration."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScanMode(str, Enum):
    """Scan mode enumeration for dual-mode scanning."""
    DOMAIN_ONLY = "domain_only"  # Fast pre-navigation scan
    FULL = "full"                # Complete content + infrastructure scan


class ScanRequest(BaseModel):
    """Request schema for threat scanning with dual-mode support."""
    text: Optional[str] = Field(None, description="Text content to scan")
    url: Optional[str] = Field(None, description="URL to scan")
    html: Optional[str] = Field(None, description="HTML content to scan")
    meta: Optional[Dict] = Field(default_factory=dict, description="Additional metadata")
    mode: ScanMode = Field(
        default=ScanMode.FULL,
        description="Scan mode: 'domain_only' for fast pre-navigation, 'full' for complete analysis"
    )
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v: Optional[str]) -> Optional[str]:
        """Validate and sanitize URL."""
        if v is None:
            return v
        try:
            parsed = urlparse(v)
            if not parsed.scheme:
                raise ValueError("URL must include a scheme (http/https)")
            if parsed.scheme not in ('http', 'https'):
                raise ValueError("URL must use http or https scheme")
            return v.lower()
        except Exception as e:
            raise ValueError(f"Invalid URL: {str(e)}")
    
    @field_validator('text', 'html')
    @classmethod
    def validate_content(cls, v: Optional[str]) -> Optional[str]:
        """Validate content length."""
        if v is not None and len(v) > 1000000:  # 1MB limit
            raise ValueError("Content too large (max 1MB)")
        return v
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "url": "https://example.com",
                "meta": {"source": "api"}
            }
        }
    }


class ScanResponse(BaseModel):
    """Response schema for threat scan results with blocking support."""
    scan_id: str = Field(..., description="Unique scan identifier")
    risk: RiskLevel = Field(..., description="Risk level assessment")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    reasons: List[str] = Field(default_factory=list, description="Explanation reasons")
    graph_score: float = Field(..., ge=0.0, le=1.0, description="Graph-based score")
    model_score: float = Field(..., ge=0.0, le=1.0, description="ML model score")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Scan timestamp")
    
    # Browser blocking fields
    block: bool = Field(default=False, description="Whether to block navigation (true only if HIGH risk)")
    domain_risk: float = Field(default=0.0, ge=0.0, le=1.0, description="Infrastructure/domain risk score")
    content_risk: float = Field(default=0.0, ge=0.0, le=1.0, description="Content/ML risk score")
    
    model_config = ConfigDict(
        protected_namespaces=(),
        json_schema_extra={
            "example": {
                "scan_id": "abc123",
                "risk": "HIGH",
                "confidence": 0.95,
                "reasons": ["Known malicious domain", "High centrality score"],
                "graph_score": 0.8,
                "model_score": 0.9,
                "timestamp": "2024-01-15T10:30:00Z",
                "block": True,
                "domain_risk": 0.95,
                "content_risk": 0.88
            }
        }
    )


class FeedbackRequest(BaseModel):
    """Request schema for user feedback on scans."""
    scan_id: str = Field(..., description="Scan identifier")
    user_flag: bool = Field(..., description="User's flag (true = malicious, false = benign)")
    corrected_label: Optional[str] = Field(None, description="Corrected label if different")
    comment: Optional[str] = Field(None, description="User comment")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "scan_id": "abc123",
                "user_flag": True,
                "corrected_label": "HIGH",
                "comment": "This is clearly a phishing site"
            }
        }
    }


class FeedbackResponse(BaseModel):
    """Response schema for feedback submission."""
    feedback_id: str = Field(..., description="Feedback identifier")
    status: str = Field(..., description="Feedback status")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HealthResponse(BaseModel):
    """Response schema for health check."""
    status: str = Field(..., description="Health status")
    version: str = Field(..., description="Application version")
    database: Optional[str] = Field(None, description="Database status")
    redis: Optional[str] = Field(None, description="Redis status")


class TokenData(BaseModel):
    """JWT token data schema."""
    sub: str = Field(..., description="Subject (user identifier)")
    exp: datetime = Field(..., description="Expiration time")
    roles: List[str] = Field(default_factory=list, description="User roles")


class User(BaseModel):
    """User schema."""
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: bool = False
    roles: List[str] = Field(default_factory=list)


class UserInDB(User):
    """User database schema with hashed password."""
    hashed_password: str


class Token(BaseModel):
    """JWT token response schema."""
    access_token: str
    token_type: str = "bearer"


class ThreatIntelResponse(BaseModel):
    """Response schema for threat intelligence data."""
    domain: str
    risk_score: float
    is_malicious: bool
    related_ips: List[str]
    related_domains: List[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    tags: List[str] = Field(default_factory=list)
    meta: Dict = Field(default_factory=dict)


class ModelHealthResponse(BaseModel):
    """Response schema for model health metrics."""
    model_config = ConfigDict(protected_namespaces=())
    
    model_name: str
    uptime: float
    total_predictions: int
    error_rate: float
    average_latency_ms: float
    last_retrain: Optional[datetime]


# ============================================
# FORENSIC API SCHEMAS
# ============================================

class ForensicScanRequest(BaseModel):
    """Request schema for forensic deep-scan analysis."""
    url: str = Field(..., description="URL to perform forensic analysis on")
    deep_analysis: bool = Field(default=True, description="Enable deep behavioral analysis")
    include_screenshots: bool = Field(default=False, description="Capture page screenshots")
    sandbox_execution: bool = Field(default=False, description="Execute in sandbox environment")
    extract_artifacts: bool = Field(default=True, description="Extract JS, forms, iframes")
    check_whois: bool = Field(default=True, description="Query WHOIS records")
    check_dns: bool = Field(default=True, description="Query DNS records")
    check_ssl: bool = Field(default=True, description="Analyze SSL certificate")
    check_threat_intel: bool = Field(default=True, description="Check threat intelligence feeds")


class ArtifactInfo(BaseModel):
    """Information about extracted artifacts."""
    type: str  # javascript, form, iframe, css, image
    source: str  # url or inline
    content: Optional[str] = None
    attributes: Dict[str, Any] = {}


class SandboxResult(BaseModel):
    """Results from sandbox execution."""
    executed: bool
    behaviors: List[str] = []
    network_requests: List[Dict] = []
    console_output: Optional[str] = None
    errors: List[str] = []
    execution_time_ms: int = 0


class WhoisInfo(BaseModel):
    """WHOIS information for domain."""
    domain_name: Optional[str] = None
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    name_servers: List[str] = []
    registrant_name: Optional[str] = None
    registrant_country: Optional[str] = None


class DnsRecord(BaseModel):
    """DNS record information."""
    record_type: str  # A, AAAA, MX, TXT, CNAME, NS
    value: str
    ttl: int = 0


class SslInfo(BaseModel):
    """SSL certificate information."""
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    days_until_expiry: Optional[int] = None
    signature_algorithm: Optional[str] = None
    is_valid: bool = True
    issues: List[str] = []


class ForensicScanResponse(BaseModel):
    """Response schema for forensic deep-scan analysis."""
    scan_id: str
    url: str
    risk: RiskLevel
    confidence: float
    
    # Analysis components
    basic_analysis: Dict[str, Any] = Field(default_factory=dict)
    behavioral_analysis: Dict[str, Any] = Field(default_factory=dict)
    
    # Extracted artifacts
    artifacts: List[ArtifactInfo] = Field(default_factory=list)
    
    # Sandbox results (if executed)
    sandbox: Optional[SandboxResult] = None
    
    # Intelligence data
    whois: Optional[WhoisInfo] = None
    dns_records: List[DnsRecord] = Field(default_factory=list)
    ssl_info: Optional[SslInfo] = None
    
    # Threat intelligence
    threat_intel_matches: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Detailed reasons
    reasons: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    
    # Metadata
    analysis_duration_ms: int = 0
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
    components_used: List[str] = Field(default_factory=list)


class ForensicSummary(BaseModel):
    """Quick summary of forensic analysis."""
    scan_id: str
    url: str
    risk: RiskLevel
    confidence: float
    key_findings: List[str]
    recommendation: str


class ForensicStatusResponse(BaseModel):
    """Status of forensic scan."""
    scan_id: str
    status: str  # pending, in_progress, completed, failed
    progress: int = 0  # 0-100
    message: Optional[str] = None


class ForensicListResponse(BaseModel):
    """List of forensic scans."""
    scans: List[ForensicSummary]
    total: int
    page: int
    page_size: int
