"""
Configuration settings for the Threat Intelligence Platform.
Environment-aware configuration with centralized settings.
"""
import os
from functools import lru_cache
from pydantic_settings import BaseSettings
from typing import List, Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Environment detection
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    # Application
    APP_NAME: str = "Threat Intelligence Platform"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    API_PREFIX: str = "/api/v1"
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 4
    
    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://postgres:postgres@localhost:5432/threat_intel"
    )
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    
    # Redis (CRITICAL: Environment-aware)
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
    
    # ✅ ADDED: Full Redis connection URL (fixes ValueError: Extra inputs are not permitted)
    # This also serves as fallback if REDIS_HOST/PORT/DB are not set
    REDIS_URL: str = os.getenv("REDIS_URL", "")
    
    # ✅ ADDED: Cache TTL (fixes ValueError: Extra inputs are not permitted)
    REDIS_CACHE_TTL: int = int(os.getenv("REDIS_CACHE_TTL", "3600"))
    
    def __init__(self, **data):
        super().__init__(**data)
        # Compute REDIS_URL from components if not explicitly provided
        if not self.REDIS_URL:
            self.REDIS_URL = f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
    
    # JWT Security
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY",
        "your-secret-key-change-in-production"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    
    # Graph Settings (MVP)
    GRAPH_CACHE_TTL: int = 3600
    GRAPH_REFRESH_INTERVAL: int = int(os.getenv("GRAPH_REFRESH_INTERVAL", "86400"))
    
    # ML Service
    ML_SERVICE_URL: str = os.getenv("ML_SERVICE_URL", "http://localhost:8001")
    ML_TIMEOUT: int = 30
    
    # Celery (MUST use explicit env var)
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL")
    if not CELERY_BROKER_URL:
        CELERY_BROKER_URL = REDIS_URL
    
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)
    
    # OpenTelemetry
    OTEL_EXPORTER_OTLP_ENDPOINT: str = os.getenv(
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "http://localhost:4317"
    )
    OTEL_SERVICE_NAME: str = "threat-intel-api"
    
    # Scoring Weights
    MODEL_WEIGHT: float = 0.6
    GRAPH_WEIGHT: float = 0.4
    
    # Threat Feeds Configuration
    THREAT_FEEDS: List[dict] = [
        {
            "name": "openphish",
            "url": os.getenv("OPENPHISH_URL", "https://openphish.com/feed.txt"),
            "enabled": os.getenv("OPENPHISH_ENABLED", "false").lower() == "true",
            "api_key": os.getenv("OPENPHISH_API_KEY", ""),
            "refresh_interval": 3600,
        },
        {
            "name": "urlhaus",
            "url": os.getenv("URLHAUS_URL", "https://urlhaus-api.abuse.ch/v1/urls/recent/"),
            "enabled": os.getenv("URLHAUS_ENABLED", "false").lower() == "true",
            "api_key": os.getenv("URLHAUS_API_KEY", ""),
            "refresh_interval": 7200,
        },
        {
            "name": "phishtank",
            "url": os.getenv("PHISHTANK_URL", "https://data.phishtank.org/data/online-valid.json"),
            "enabled": os.getenv("PHISHTANK_ENABLED", "false").lower() == "true",
            "api_key": os.getenv("PHISHTANK_API_KEY", ""),
            "refresh_interval": 3600,
        },
    ]
    
    # Retention
    SCAN_RETENTION_DAYS: int = int(os.getenv("SCAN_RETENTION_DAYS", "90"))
    
    model_config = {
        "extra": "ignore",
        "env_file": ".env",
        "case_sensitive": True,
    }


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
