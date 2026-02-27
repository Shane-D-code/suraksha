"""
Services package for business logic.
"""
from app.services.database import get_db_session, init_db, close_db
from app.services.redis import get_redis_client, init_redis, close_redis
from app.services.graph import GraphService
from app.services.scoring import compute_final_score
from app.services.threat_data_loader import ThreatDataLoader, RealTimeThreatChecker, KNOWN_PHISHING_DOMAINS
from app.services.threat_feeds import (
    ThreatFeedAggregator,
    ThreatIndicator,
    get_feed_aggregator,
    fetch_all_threat_feeds,
    BaseFeedProvider,
    OpenPhishFeed,
    URLhausFeed,
    PhishTankFeed,
)

__all__ = [
    # Database
    "get_db_session",
    "init_db",
    "close_db",
    # Redis
    "get_redis_client",
    "init_redis",
    "close_redis",
    # Graph
    "GraphService",
    # Scoring
    "compute_final_score",
    # Threat Data Loader
    "ThreatDataLoader",
    "RealTimeThreatChecker",
    "KNOWN_PHISHING_DOMAINS",
    # Threat Feeds
    "ThreatFeedAggregator",
    "ThreatIndicator",
    "get_feed_aggregator",
    "fetch_all_threat_feeds",
    "BaseFeedProvider",
    "OpenPhishFeed",
    "URLhausFeed",
    "PhishTankFeed",
]
