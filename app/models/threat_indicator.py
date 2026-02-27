"""
Threat Indicator database model.
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Enum as SQLEnum
from sqlalchemy.sql import func
import enum

from app.models.db import Base


class ThreatTypeEnum(enum.Enum):
    """Types of threats"""
    PHISHING = "phishing"
    MALWARE = "malware"
    SPAM = "spam"
    CRYPTO_SCAM = "crypto_scam"
    CREDENTIAL_THEFT = "credential_theft"


class ThreatIndicator(Base):
    """
    Threat indicator table for storing external IOC feed data.
    """
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(String(2048), nullable=True, index=True)  # Full URL or indicator value
    domain = Column(String(255), nullable=True, index=True)  # Extracted domain
    indicator_type = Column(String(50), nullable=False, default="domain")  # domain, url, ip
    ip_address = Column(String(45), nullable=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    threat_type = Column(String(50), nullable=False, default="phishing")
    source = Column(String(100), nullable=False)  # phishtank, openphish, urlhaus, etc.
    first_seen = Column(DateTime, nullable=False)
    last_updated = Column(DateTime, nullable=True, onupdate=func.now())
    tags = Column(JSON, nullable=True)
    extra_data = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<ThreatIndicator(domain={self.domain}, value={self.value}, type={self.indicator_type}, source={self.source})>"
