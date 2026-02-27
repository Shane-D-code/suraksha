"""
Real-time dashboard database models.
"""
import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, 
    Index, ForeignKey, JSON, Enum as SQLEnum
)
from sqlalchemy.orm import relationship, declarative_base
import enum

Base = declarative_base()


class ScanStatusEnum(str, enum.Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ThreatLevelEnum(str, enum.Enum):
    """Threat level enumeration."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanTypeEnum(str, enum.Enum):
    """Scan type enumeration."""
    URL = "url"
    EMAIL = "email"
    SCREENSHOT = "screenshot"
    MESSAGE = "message"


class ScanEventTypeEnum(str, enum.Enum):
    """Real-time event type enumeration."""
    SCAN_STARTED = "scan_started"
    SCAN_PROGRESS = "scan_progress"
    SCAN_COMPLETED = "scan_completed"
    THREAT_DETECTED = "threat_detected"
    ALERT_TRIGGERED = "alert_triggered"


class ThreatTypeEnum(str, enum.Enum):
    """Threat type enumeration."""
    PHISHING = "phishing"
    MALWARE = "malware"
    DEFACEMENT = "defacement"
    SPAM = "spam"
    IMPERSONATION = "impersonation"
    ZERO_DAY = "zero_day"


class IocTypeEnum(str, enum.Enum):
    """Indicator of Compromise type."""
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    HASH = "hash"
    EMAIL = "email"


class Scan(Base):
    """Scan results table with real-time tracking."""
    __tablename__ = "realtime_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(36), unique=True, index=True, nullable=False, default=lambda: str(uuid.uuid4()))
    
    # Input
    url = Column(Text, nullable=True)
    scan_type = Column(SQLEnum(ScanTypeEnum), default=ScanTypeEnum.URL)
    source = Column(String(100), default="api")  # extension, api, email_scanner, manual
    
    # Status tracking
    status = Column(SQLEnum(ScanStatusEnum), default=ScanStatusEnum.PENDING, index=True)
    risk_score = Column(Float, default=0.0, index=True)
    threat_level = Column(SQLEnum(ThreatLevelEnum), default=ThreatLevelEnum.LOW, index=True)
    
    # Timing
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)
    processing_time_ms = Column(Integer, nullable=True)
    
    # User
    user_id = Column(String(36), nullable=True, index=True)
    
    # Metadata
    metadata = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)
    
    # Relationships
    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")
    threats = relationship("Threat", back_populates="scan", cascade="all, delete-orphan")
    events = relationship("RealTimeEvent", back_populates="scan", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_realtime_scans_created', 'created_at.desc()'),
        Index('idx_realtime_scans_risk', 'risk_score.desc()'),
        Index('idx_realtime_scans_status_threat', 'status', 'threat_level'),
    )


class ScanResult(Base):
    """Individual scan component results."""
    __tablename__ = "realtime_scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    result_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("realtime_scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Component identification
    component = Column(String(50), nullable=False)  # nlp, url, visual, graph, anomaly
    
    # Scores
    score = Column(Float, nullable=False)
    confidence = Column(Float, default=0.0)
    
    # Details
    details = Column(JSON, not_nullable=False, default=dict)
    reasons = Column(JSON, default=list)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="results")
    
    # Indexes
    __table_args__ = (
        Index('idx_results_scan_component', 'scan_id', 'component'),
    )


class Threat(Base):
    """Detected threats table."""
    __tablename__ = "realtime_threats"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("realtime_scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Threat classification
    threat_type = Column(SQLEnum(ThreatTypeEnum), nullable=False, index=True)
    threat_category = Column(String(50), nullable=True)
    severity = Column(SQLEnum(ThreatLevelEnum), default=ThreatLevelEnum.MEDIUM, index=True)
    
    # Indicator of Compromise
    ioc_type = Column(SQLEnum(IocTypeEnum), nullable=False)
    ioc_value = Column(Text, nullable=False, index=True)
    
    # Details
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    
    # Resolution tracking
    resolved = Column(Boolean, default=False, index=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(36), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    scan = relationship("Scan", back_populates="threats")
    
    # Indexes
    __table_args__ = (
        Index('idx_threats_ioc_type', 'ioc_type', 'ioc_value'),
        Index('idx_threats_resolved', 'resolved', 'severity'),
    )


class DashboardMetric(Base):
    """Dashboard aggregated metrics table."""
    __tablename__ = "dashboard_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    metric_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    
    # Metric identification
    metric_type = Column(String(50), nullable=False, index=True)  # total_scans, threats_blocked, avg_risk_score
    category = Column(String(50), nullable=True, index=True)  # For filtering by scan_type, threat_type
    
    # Value
    metric_value = Column(Float, nullable=False)
    
    # Time bucket (hourly/daily)
    time_bucket = Column(DateTime, nullable=False, index=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Indexes
    __table_args__ = (
        Index('idx_metrics_bucket_type', 'time_bucket.desc(), metric_type'),
    )


class RealTimeEvent(Base):
    """Real-time events for WebSocket broadcasting."""
    __tablename__ = "realtime_events"
    
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    
    # Event identification
    event_type = Column(SQLEnum(ScanEventTypeEnum), nullable=False, index=True)
    scan_id = Column(String(36), ForeignKey("realtime_scans.scan_id", ondelete="CASCADE"), nullable=True, index=True)
    
    # Payload
    payload = Column(JSON, nullable=False)
    broadcasted = Column(Boolean, default=False, index=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    scan = relationship("Scan", back_populates="events")
    
    # Indexes
    __table_args__ = (
        Index('idx_events_broadcast', 'broadcasted', 'created_at.desc()'),
    )


# Helper function to create all tables
def create_realtime_tables(engine):
    """Create all real-time tables."""
    Base.metadata.create_all(engine)
