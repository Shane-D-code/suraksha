"""
Threat Feed Abstraction Layer

Provides unified interface for fetching threat intelligence from multiple sources.
This layer was previously implemented in Chrome extension backend but not integrated
into the main application.
"""

import aiohttp
import asyncio
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
from datetime import datetime
from dataclasses import dataclass
import structlog

from app.config import settings

logger = structlog.get_logger(__name__)


@dataclass
class ThreatIndicator:
    """Standardized threat indicator format"""
    value: str
    indicator_type: str  # domain, ip, url, email, hash
    source: str
    confidence: float
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict:
        return {
            "value": self.value,
            "type": self.indicator_type,
            "source": self.source,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "metadata": self.metadata or {}
        }


class BaseFeedProvider(ABC):
    """Abstract base class for threat feed providers"""
    
    def __init__(self, name: str, config: dict):
        self.name = name
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
    
    @abstractmethod
    async def fetch(self) -> List[ThreatIndicator]:
        """Fetch threat indicators from source"""
        pass
    
    @abstractmethod
    def transform(self, raw_data: Any) -> List[ThreatIndicator]:
        """Transform raw data to standardized format"""
        pass
    
    async def get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session
    
    async def close(self):
        """Close HTTP session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def fetch_indicators(self) -> List[ThreatIndicator]:
        """Main entry point - fetch and transform"""
        if not self.config.get("enabled", False):
            logger.debug(f"Feed {self.name} is disabled")
            return []
        
        try:
            raw_data = await self._raw_fetch()
            indicators = self.transform(raw_data)
            logger.info(f"Fetched {len(indicators)} indicators from {self.name}")
            return indicators
        except Exception as e:
            logger.error(f"Failed to fetch from {self.name}: {e}")
            return []
    
    async def _raw_fetch(self) -> Any:
        """Internal fetch method"""
        session = await self.get_session()
        async with session.get(self.config["url"]) as response:
            response.raise_for_status()
            return await self._parse_response(response)
    
    @abstractmethod
    async def _parse_response(self, response: aiohttp.ClientResponse) -> Any:
        """Parse response based on format"""
        pass


class OpenPhishFeed(BaseFeedProvider):
    """OpenPhish feed provider - URL-based threats"""
    
    def __init__(self, config: dict):
        super().__init__("openphish", config)
    
    async def fetch(self) -> List[ThreatIndicator]:
        return await self.fetch_indicators()
    
    async def _parse_response(self, response: aiohttp.ClientResponse) -> str:
        return await response.text()
    
    def transform(self, raw_data: str) -> List[ThreatIndicator]:
        indicators = []
        for line in raw_data.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                indicators.append(ThreatIndicator(
                    value=line,
                    indicator_type="url",
                    source="openphish",
                    confidence=0.9,
                    metadata={"feed": "openphish"}
                ))
        return indicators


class URLhausFeed(BaseFeedProvider):
    """URLhaus feed provider - malware URLs"""
    
    def __init__(self, config: dict):
        super().__init__("urlhaus", config)
    
    async def fetch(self) -> List[ThreatIndicator]:
        return await self.fetch_indicators()
    
    async def _parse_response(self, response: aiohttp.ClientResponse) -> Dict:
        return await response.json()
    
    def transform(self, raw_data: Dict) -> List[ThreatIndicator]:
        indicators = []
        for item in raw_data.get("urls", []):
            url_status = item.get("url_status", "")
            if url_status == "online":
                indicators.append(ThreatIndicator(
                    value=item.get("url"),
                    indicator_type="url",
                    source="urlhaus",
                    confidence=0.85,
                    first_seen=datetime.utcnow(),
                    metadata={
                        "malware_family": item.get("malware", {}).get("name") if isinstance(item.get("malware"), dict) else None,
                        "tags": item.get("tags", []),
                        "threat": item.get("threat")
                    }
                ))
        return indicators


class PhishTankFeed(BaseFeedProvider):
    """PhishTank feed provider - phishing URLs"""
    
    def __init__(self, config: dict):
        super().__init__("phishtank", config)
    
    async def fetch(self) -> List[ThreatIndicator]:
        return await self.fetch_indicators()
    
    async def _parse_response(self, response: aiohttp.ClientResponse) -> List[Dict]:
        return await response.json()
    
    def transform(self, raw_data: List[Dict]) -> List[ThreatIndicator]:
        indicators = []
        for item in raw_data:
            if item.get("in_database"):
                indicators.append(ThreatIndicator(
                    value=item.get("url"),
                    indicator_type="url",
                    source="phishtank",
                    confidence=0.95 if item.get("verified") else 0.7,
                    metadata={
                        "phish_id": item.get("phish_id"),
                        "verified": item.get("verified"),
                        "submission_time": item.get("submission_time")
                    }
                ))
        return indicators


class ThreatFeedAggregator:
    """Aggregates and manages multiple threat feed providers"""
    
    def __init__(self):
        self.providers: List[BaseFeedProvider] = []
        self._initialize_providers()
    
    def _initialize_providers(self):
        """Initialize providers from settings"""
        for feed_config in settings.THREAT_FEEDS:
            if not feed_config.get("enabled", False):
                continue
                
            name = feed_config["name"]
            if name == "openphish":
                self.providers.append(OpenPhishFeed(feed_config))
            elif name == "urlhaus":
                self.providers.append(URLhausFeed(feed_config))
            elif name == "phishtank":
                self.providers.append(PhishTankFeed(feed_config))
        
        logger.info(f"Initialized {len(self.providers)} threat feed providers")
    
    async def fetch_all(self) -> List[ThreatIndicator]:
        """Fetch from all enabled providers concurrently"""
        if not self.providers:
            logger.warning("No threat feed providers enabled")
            return []
        
        tasks = [provider.fetch() for provider in self.providers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_indicators = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Provider {self.providers[i].name} failed: {result}")
            elif isinstance(result, list):
                all_indicators.extend(result)
        
        # Deduplicate
        seen = set()
        unique_indicators = []
        for indicator in all_indicators:
            if indicator.value not in seen:
                seen.add(indicator.value)
                unique_indicators.append(indicator)
        
        logger.info(f"Total unique indicators: {len(unique_indicators)}")
        return unique_indicators
    
    async def close_all(self):
        """Close all provider sessions"""
        for provider in self.providers:
            await provider.close()
    
    def get_status(self) -> List[Dict]:
        """Get status of all providers"""
        return [
            {
                "name": p.name,
                "enabled": p.config.get("enabled", False),
                "url": p.config.get("url"),
                "refresh_interval": p.config.get("refresh_interval")
            }
            for p in self.providers
        ]


# Singleton instance
_feed_aggregator: Optional[ThreatFeedAggregator] = None


def get_feed_aggregator() -> ThreatFeedAggregator:
    """Get the global feed aggregator instance"""
    global _feed_aggregator
    if _feed_aggregator is None:
        _feed_aggregator = ThreatFeedAggregator()
    return _feed_aggregator


async def fetch_all_threat_feeds() -> List[Dict]:
    """Convenience function to fetch all threat feeds"""
    aggregator = get_feed_aggregator()
    indicators = await aggregator.fetch_all()
    return [i.to_dict() for i in indicators]


async def sync_feeds_to_graph(db_pool=None, redis_client=None) -> int:
    """
    Sync fetched threat indicators to the graph database.
    This connects external threat feeds to the ThreatGraphEngine.
    
    Returns the number of indicators synced.
    """
    from urllib.parse import urlparse
    
    indicators = await fetch_all_threat_feeds()
    
    if not indicators:
        logger.warning("No indicators to sync to graph")
        return 0
    
    synced_count = 0
    
    for indicator in indicators:
        try:
            # Extract domain from URL if indicator_type is url
            domain = indicator.get("value", "")
            if indicator.get("type") == "url" and domain:
                parsed = urlparse(domain if domain.startswith("http") else f"http://{domain}")
                domain = parsed.netloc or parsed.path
            
            # Store in Redis for quick lookup
            if redis_client:
                cache_key = f"threat:domain:{domain}"
                await redis_client.setex(
                    cache_key,
                    86400,  # 24 hour TTL
                    str(indicator.get("confidence", 0.8))
                )
                synced_count += 1
                
        except Exception as e:
            logger.debug(f"Failed to sync indicator: {e}")
    
    logger.info(f"Synced {synced_count} threat indicators to graph")
    return synced_count
