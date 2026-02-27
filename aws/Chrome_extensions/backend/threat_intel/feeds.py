"""
PhishGuard Threat Intelligence Feed Ingestion Engine
Continuously ingests live phishing threat feeds and maintains threat database
"""

import asyncio
import aiohttp
import hashlib
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatFeed:
    """Base class for threat feed sources"""
    
    def __init__(self, name: str, url: str, confidence: float = 0.8):
        self.name = name
        self.url = url
        self.confidence = confidence
        self.last_fetch = None
        
    async def fetch(self) -> List[Dict]:
        """Fetch and parse threat feed"""
        raise NotImplementedError
        
    def normalize_domain(self, url: str) -> Optional[str]:
        """Extract and normalize domain from URL"""
        try:
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            domain = parsed.netloc or parsed.path
            return domain.lower().strip()
        except Exception as e:
            logger.warning(f"Failed to parse URL {url}: {e}")
            return None


class PhishTankFeed(ThreatFeed):
    """PhishTank public feed (example)"""
    
    def __init__(self):
        super().__init__(
            name="PhishTank",
            url="http://data.phishtank.com/data/online-valid.json",
            confidence=0.9
        )
    
    async def fetch(self) -> List[Dict]:
        """Fetch PhishTank feed"""
        threats = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for entry in data[:1000]:  # Limit for demo
                            domain = self.normalize_domain(entry.get('url', ''))
                            if domain:
                                threats.append({
                                    'domain': domain,
                                    'url': entry.get('url'),
                                    'source': self.name,
                                    'confidence': self.confidence,
                                    'first_seen': datetime.now(),
                                    'verified': entry.get('verified', False)
                                })
                        
                        self.last_fetch = datetime.now()
                        logger.info(f"Fetched {len(threats)} threats from {self.name}")
                        
        except Exception as e:
            logger.error(f"Failed to fetch {self.name}: {e}")
            
        return threats


class OpenPhishFeed(ThreatFeed):
    """OpenPhish public feed"""
    
    def __init__(self):
        super().__init__(
            name="OpenPhish",
            url="https://openphish.com/feed.txt",
            confidence=0.85
        )
    
    async def fetch(self) -> List[Dict]:
        """Fetch OpenPhish feed"""
        threats = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.url, timeout=30) as response:
                    if response.status == 200:
                        text = await response.text()
                        urls = text.strip().split('\n')
                        
                        for url in urls[:1000]:  # Limit for demo
                            domain = self.normalize_domain(url)
                            if domain:
                                threats.append({
                                    'domain': domain,
                                    'url': url,
                                    'source': self.name,
                                    'confidence': self.confidence,
                                    'first_seen': datetime.now()
                                })
                        
                        self.last_fetch = datetime.now()
                        logger.info(f"Fetched {len(threats)} threats from {self.name}")
                        
        except Exception as e:
            logger.error(f"Failed to fetch {self.name}: {e}")
            
        return threats


class CustomFeed(ThreatFeed):
    """Custom curated threat feed"""
    
    def __init__(self, filepath: str):
        super().__init__(
            name="Custom",
            url=filepath,
            confidence=0.95
        )
        self.filepath = filepath
    
    async def fetch(self) -> List[Dict]:
        """Load custom threat list from file"""
        threats = []
        
        try:
            with open(self.filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        domain = self.normalize_domain(line)
                        if domain:
                            threats.append({
                                'domain': domain,
                                'source': self.name,
                                'confidence': self.confidence,
                                'first_seen': datetime.now()
                            })
            
            self.last_fetch = datetime.now()
            logger.info(f"Loaded {len(threats)} threats from {self.name}")
            
        except FileNotFoundError:
            logger.warning(f"Custom feed file not found: {self.filepath}")
        except Exception as e:
            logger.error(f"Failed to load {self.name}: {e}")
            
        return threats


class ThreatFeedAggregator:
    """Aggregates multiple threat feeds"""
    
    def __init__(self):
        self.feeds: List[ThreatFeed] = []
        self.seen_domains: Set[str] = set()
        
    def add_feed(self, feed: ThreatFeed):
        """Add a threat feed source"""
        self.feeds.append(feed)
        logger.info(f"Added feed: {feed.name}")
        
    async def fetch_all(self) -> List[Dict]:
        """Fetch from all feeds concurrently"""
        logger.info(f"Fetching from {len(self.feeds)} feeds...")
        
        tasks = [feed.fetch() for feed in self.feeds]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_threats = []
        for result in results:
            if isinstance(result, list):
                all_threats.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"Feed fetch failed: {result}")
        
        # Deduplicate by domain
        unique_threats = self._deduplicate(all_threats)
        
        logger.info(f"Fetched {len(unique_threats)} unique threats")
        return unique_threats
    
    def _deduplicate(self, threats: List[Dict]) -> List[Dict]:
        """Remove duplicate domains, keeping highest confidence"""
        domain_map = {}
        
        for threat in threats:
            domain = threat['domain']
            
            if domain not in domain_map:
                domain_map[domain] = threat
            else:
                # Keep threat with higher confidence
                if threat['confidence'] > domain_map[domain]['confidence']:
                    domain_map[domain] = threat
        
        return list(domain_map.values())
    
    def get_feed_status(self) -> List[Dict]:
        """Get status of all feeds"""
        status = []
        for feed in self.feeds:
            status.append({
                'name': feed.name,
                'last_fetch': feed.last_fetch.isoformat() if feed.last_fetch else None,
                'confidence': feed.confidence
            })
        return status


class ThreatEnricher:
    """Enriches threat data with additional intelligence"""
    
    @staticmethod
    def extract_ip(domain: str) -> Optional[str]:
        """Extract IP address from domain (placeholder)"""
        # In production, use DNS lookup
        # import socket
        # try:
        #     return socket.gethostbyname(domain)
        # except:
        #     return None
        return None
    
    @staticmethod
    def calculate_domain_hash(domain: str) -> str:
        """Calculate hash of domain for tracking"""
        return hashlib.sha256(domain.encode()).hexdigest()[:16]
    
    @staticmethod
    def extract_tld(domain: str) -> str:
        """Extract top-level domain"""
        parts = domain.split('.')
        return parts[-1] if parts else ''
    
    @staticmethod
    def is_suspicious_tld(domain: str) -> bool:
        """Check if TLD is commonly used in phishing"""
        suspicious_tlds = {
            'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs
            'xyz', 'top', 'work', 'click'   # Cheap TLDs
        }
        tld = ThreatEnricher.extract_tld(domain)
        return tld in suspicious_tlds
    
    @staticmethod
    async def enrich_threat(threat: Dict) -> Dict:
        """Enrich threat with additional data"""
        domain = threat['domain']
        
        threat['domain_hash'] = ThreatEnricher.calculate_domain_hash(domain)
        threat['tld'] = ThreatEnricher.extract_tld(domain)
        threat['suspicious_tld'] = ThreatEnricher.is_suspicious_tld(domain)
        threat['domain_length'] = len(domain)
        threat['subdomain_count'] = len(domain.split('.')) - 2
        
        # IP lookup (disabled for demo to avoid DNS queries)
        # threat['ip'] = ThreatEnricher.extract_ip(domain)
        
        return threat


# Example usage
async def main():
    """Example threat feed ingestion"""
    aggregator = ThreatFeedAggregator()
    
    # Add feeds
    # aggregator.add_feed(PhishTankFeed())
    # aggregator.add_feed(OpenPhishFeed())
    aggregator.add_feed(CustomFeed('threat_feeds/custom_threats.txt'))
    
    # Fetch threats
    threats = await aggregator.fetch_all()
    
    # Enrich threats
    enriched = []
    for threat in threats[:10]:  # Demo: first 10
        enriched_threat = await ThreatEnricher.enrich_threat(threat)
        enriched.append(enriched_threat)
    
    # Display results
    for threat in enriched:
        print(f"Domain: {threat['domain']}")
        print(f"  Source: {threat['source']}")
        print(f"  Confidence: {threat['confidence']}")
        print(f"  Hash: {threat['domain_hash']}")
        print(f"  TLD: {threat['tld']} (suspicious: {threat['suspicious_tld']})")
        print()
    
    # Feed status
    print("\nFeed Status:")
    for status in aggregator.get_feed_status():
        print(f"  {status['name']}: {status['last_fetch'] or 'Never'}")


if __name__ == '__main__':
    asyncio.run(main())
