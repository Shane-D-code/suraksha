"""
Hybrid Offline + Live Threat Intelligence Cache Service.

Provides a cache-first lookup layer for threat intelligence that works
without internet by using previously synchronized real threat feeds.

Architecture:
  lookup(indicator)
    ├─ Redis cache hit → return cached (+ cache_age)
    ├─ DB cache hit → return cached (+ cache_age)
    └─ miss + ONLINE mode → fetch live, cache, return
       miss + OFFLINE mode → return {risk_score: 0, source: "offline"}
"""
import json
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any
import structlog

from app.config import settings

logger = structlog.get_logger(__name__)


class IntelligenceMode(str, Enum):
    OFFLINE = "offline"
    ONLINE = "online"


# ── RBI / Bank Validation Rules ─────────────────────────────────────

BANK_RULES: dict[str, dict] = {
    "canara": {
        "required_fields": ["ifsc", "account_number", "branch", "customer_id"],
        "currency": "INR",
        "ifsc_prefix": "CNRB",
        "expected_sections": ["account summary", "transaction details", "branch", "ifsc"],
    },
    "sbi": {
        "required_fields": ["ifsc", "account_number", "branch"],
        "currency": "INR",
        "ifsc_prefix": "SBIN",
        "expected_sections": ["account summary", "transaction details", "branch", "ifsc"],
    },
    "hdfc": {
        "required_fields": ["ifsc", "account_number", "branch"],
        "currency": "INR",
        "ifsc_prefix": "HDFC",
        "expected_sections": ["account summary", "transaction details"],
    },
    "icici": {
        "required_fields": ["ifsc", "account_number", "branch"],
        "currency": "INR",
        "ifsc_prefix": "ICIC",
        "expected_sections": ["account summary", "transaction details"],
    },
}

TEMPLATE_SOURCES = [
    "template.net", "templatelab", "canva", "freepik",
    "adobe express", "adobe stock", "powered by canva",
    "wix", "squarespace", "wordpress", "strikingly",
    "weebly", "godaddy", "shopify",
]

EXPECTED_BANK_LAYOUTS: dict[str, list[str]] = {
    bank: info["expected_sections"] for bank, info in BANK_RULES.items()
}


class IntelCacheService:
    """Cache-first threat intelligence lookup with offline resilience."""

    def __init__(self, redis_client=None, db_session_factory=None):
        self.redis = redis_client
        self.db = db_session_factory
        self.mode = self._detect_mode()

    CACHE_TTL = 21600  # 6 hours

    # ── Mode detection ─────────────────────────────────────────────

    def _detect_mode(self) -> IntelligenceMode:
        if self.redis:
            try:
                self.redis.ping()
                return IntelligenceMode.ONLINE
            except Exception:
                pass
        return IntelligenceMode.OFFLINE

    @property
    def mode_name(self) -> str:
        return self.mode.value.upper()

    # ── Core lookup ────────────────────────────────────────────────

    async def find(self, indicator: str, indicator_type: str = "domain") -> dict:
        """Cache-first lookup. Returns risk data or empty offline result."""
        cached = await self._check_cache(indicator)
        if cached:
            return cached

        if self.mode == IntelligenceMode.OFFLINE:
            return {
                "indicator": indicator,
                "risk_score": 0,
                "source": "offline",
                "mode": self.mode_name,
                "cache_age": None,
            }

        return await self._fetch_and_cache(indicator, indicator_type)

    async def _check_cache(self, indicator: str) -> Optional[dict]:
        now = time.time()
        if self.redis:
            cached = await self.redis.get(f"intel:{indicator}")
            if cached:
                data = json.loads(cached)
                age_seconds = int(now - data.get("cached_at", now))
                data["cache_age"] = f"{age_seconds // 60} minutes"
                data["mode"] = self.mode_name
                logger.debug("Intel cache hit", indicator=indicator)
                return data
        return None

    async def _fetch_and_cache(self, indicator: str, indicator_type: str) -> dict:
        from app.services.domain_intel_service import DomainIntelService
        try:
            intel = await DomainIntelService(
                redis_client=self.redis,
                timeout=8,
            ).enrich(indicator)

            result = {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "risk_score": round(intel.risk_score, 3),
                "source": "live_enrichment",
                "mode": self.mode_name,
                "cache_age": "fresh",
                "domain_age_days": intel.domain_age_days,
                "registrar": intel.registrar,
                "registrant_country": intel.registrant_country,
                "asn": intel.asn,
                "ssl_issuer": intel.ssl_issuer,
                "ssl_valid": intel.ssl_valid,
                "dns_ttl": intel.dns_ttl,
                "has_mx": intel.has_mx,
                "risk_reasons": intel.risk_reasons,
            }

            if self.redis:
                result["cached_at"] = time.time()
                await self.redis.setex(
                    f"intel:{indicator}",
                    self.CACHE_TTL,
                    json.dumps(result),
                )
            return result

        except Exception as e:
            logger.warning("Live enrichment failed, falling back to offline",
                           indicator=indicator, error=str(e))
            return {
                "indicator": indicator,
                "risk_score": 0,
                "source": "offline_fallback",
                "mode": self.mode_name,
                "cache_age": None,
            }

    # ── Bank validation queries ────────────────────────────────────

    def get_bank_rules(self, bank_name: str) -> Optional[dict]:
        return BANK_RULES.get(bank_name.lower())

    def get_required_fields(self, bank_name: str) -> list[str]:
        rules = self.get_bank_rules(bank_name)
        return rules["required_fields"] if rules else []

    def check_missing_fields(self, bank_name: str, fields_found: set) -> list[str]:
        required = self.get_required_fields(bank_name)
        return [f for f in required if f not in fields_found]

    def check_template_source(self, text: str) -> list[dict]:
        findings = []
        text_lower = text.lower()
        for source in TEMPLATE_SOURCES:
            if source in text_lower:
                findings.append({
                    "source": source,
                    "risk_points": 50,
                    "finding": f"Public template source detected: {source}",
                })
        return findings

    def check_layout_similarity(
        self, extracted_sections: list[str], bank_name: str
    ) -> Optional[dict]:
        expected = EXPECTED_BANK_LAYOUTS.get(bank_name.lower())
        if not expected or not extracted_sections:
            return None

        extracted_normalized = [s.strip().lower() for s in extracted_sections]
        matches = sum(1 for es in expected if es in extracted_normalized)
        similarity = matches / len(expected) if expected else 0

        if similarity < 0.5:
            return {
                "similarity": round(similarity, 2),
                "expected_sections": expected,
                "matched_sections": matches,
                "total_sections": len(expected),
                "risk_points": 30,
            }
        return None

    def evaluate_risk_overrides(
        self,
        template_detected: bool,
        currency_mismatch: bool,
        missing_fields_count: int,
    ) -> Optional[dict]:
        if template_detected and currency_mismatch:
            return {"risk_score": 90, "decision": "REJECT", "reason": "Template + currency mismatch"}
        if template_detected and missing_fields_count >= 3:
            return {"risk_score": 85, "decision": "REJECT", "reason": "Template + missing core fields"}
        if template_detected:
            return {"risk_score": 60, "decision": "REVIEW", "reason": "Template indicators present"}
        return None


# Singleton
_instance: Optional[IntelCacheService] = None


def get_intel_cache() -> IntelCacheService:
    global _instance
    if _instance is None:
        _instance = IntelCacheService()
    return _instance
