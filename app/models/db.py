"""
SQLAlchemy database models.
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


class RiskLevelEnum(str, enum.Enum):
    """Risk level enumeration for database."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class OverrideActionEnum(str, enum.Enum):
    """Override action enumeration."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class PolicyModeEnum(str, enum.Enum):
    """Policy mode enumeration for enforcement."""
    STRICT = "STRICT"      # Block HIGH and MEDIUM
    BALANCED = "BALANCED"  # Block HIGH, Warn MEDIUM
    PERMISSIVE = "PERMISSIVE"  # Block only known_malicious, Warn HIGH, Allow MEDIUM


class Scan(Base):
    """Scan results table."""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(64), unique=True, index=True, nullable=False)
    input_hash = Column(String(64), index=True, nullable=False)
    
    # Input type
    text = Column(Text, nullable=True)
    url = Column(String(2048), nullable=True)
    html = Column(Text, nullable=True)
    
    # Results
    risk = Column(SQLEnum(RiskLevelEnum), nullable=False)
    confidence = Column(Float, nullable=False)
    graph_score = Column(Float, nullable=False)
    model_score = Column(Float, nullable=False)
    reasons = Column(JSON, default=list)
    
    # Metadata
    meta = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    feedback = relationship("Feedback", back_populates="scan", uselist=False)


class Feedback(Base):
    """User feedback on scan results."""
    __tablename__ = "feedback"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(64), ForeignKey("scans.scan_id"), nullable=False, index=True)
    user_flag = Column(Boolean, nullable=False)
    corrected_label = Column(String(32), nullable=True)
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    scan = relationship("Scan", back_populates="feedback")


class Domain(Base):
    """Domain intelligence table."""
    __tablename__ = "domains"
    
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(512), unique=True, index=True, nullable=False)
    risk_score = Column(Float, default=0.0)
    is_malicious = Column(Boolean, default=False)
    
    # Intelligence
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    registration_date = Column(DateTime, nullable=True)
    
    # Metadata
    tags = Column(JSON, default=list)
    meta = Column(JSON, default=dict)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    relations_as_source = relationship("Relation", foreign_keys="Relation.source_domain_id", back_populates="source_domain")
    relations_as_target = relationship("Relation", foreign_keys="Relation.target_domain_id", back_populates="target_domain")


class Relation(Base):
    """Domain/IP relations table."""
    __tablename__ = "relations"
    
    id = Column(Integer, primary_key=True, index=True)
    source_domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False, index=True)
    target_domain_id = Column(Integer, ForeignKey("domains.id"), nullable=True, index=True)
    target_ip = Column(String(45), nullable=True, index=True)
    
    # Relation type
    relation_type = Column(String(64), nullable=False)  # RESOLVES_TO, REDIRECTS_TO, etc.
    
    # Metadata
    meta = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    source_domain = relationship("Domain", foreign_keys=[source_domain_id], back_populates="relations_as_source")
    target_domain = relationship("Domain", foreign_keys=[target_domain_id], back_populates="relations_as_target")


class ModelMetadata(Base):
    """ML model metadata table."""
    __tablename__ = "model_metadata"
    
    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String(128), unique=True, index=True, nullable=False)
    model_version = Column(String(64), nullable=False)
    
    # Metrics
    accuracy = Column(Float, nullable=True)
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    
    # Training info
    training_data_size = Column(Integer, nullable=True)
    last_training_date = Column(DateTime, nullable=True)
    last_retrain_date = Column(DateTime, nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ThreatFeed(Base):
    """Threat feed configuration table."""
    __tablename__ = "threat_feeds"
    
    id = Column(Integer, primary_key=True, index=True)
    feed_name = Column(String(128), unique=True, index=True, nullable=False)
    feed_url = Column(String(2048), nullable=False)
    feed_type = Column(String(64), nullable=False)  # PHISHING, MALWARE, etc.
    
    # Scheduling
    fetch_interval_hours = Column(Integer, default=24)
    last_fetch = Column(DateTime, nullable=True)
    next_fetch = Column(DateTime, nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class EnterpriseOverride(Base):
    """
    Enterprise override table for domain-specific policies.
    
    This allows security administrators to explicitly allow or block
    specific domains, overriding the detection engine's judgment.
    
    IMPORTANT: This is separate from detection logic - overrides are
    applied AFTER detection, not instead of it.
    """
    __tablename__ = "enterprise_overrides"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    domain = Column(String(512), nullable=False, index=True)
    action = Column(SQLEnum(OverrideActionEnum), nullable=False)
    reason = Column(Text, nullable=True)
    created_by = Column(String(128), nullable=False)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Index for efficient lookup of active overrides
    __table_args__ = (
        Index('idx_overrides_domain_active', 'domain', postgresql_where=(expires_at > datetime.utcnow())),
    )


class PolicySettings(Base):
    """
    System-wide policy settings for enforcement.
    
    Stores the current policy mode that determines how detection
    results are translated into blocking decisions.
    """
    __tablename__ = "policy_settings"
    
    id = Column(Integer, primary_key=True)
    policy_mode = Column(SQLEnum(PolicyModeEnum), default=PolicyModeEnum.BALANCED, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(String(128), nullable=True)


# Define indexes for performance
Index('idx_scans_created_at', Scan.created_at.desc())
Index('idx_scans_risk', Scan.risk)
Index('idx_domains_risk_score', Domain.risk_score.desc())
Index('idx_relations_type', Relation.relation_type)
Index('idx_overrides_domain', EnterpriseOverride.domain)
