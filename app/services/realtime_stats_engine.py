"""
Real-Time Statistics Engine for Dashboard

This module provides live statistics calculation and Redis caching
for real-time dashboard updates.
"""
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from decimal import Decimal
import structlog

logger = structlog.get_logger(__name__)

# Redis key constants
SCAN_QUEUE_KEY = "phishing:scan_queue"
SCAN_RESULTS_KEY = "phishing:scan_results:{scan_id}"
LIVE_STATS_KEY = "phishing:live_stats"
ACTIVE_CONNECTIONS_KEY = "phishing:active_connections"
RECENT_SCANS_KEY = "phishing:recent_scans"
THREAT_ALERTS_KEY = "phishing:threat_alerts"
STATS_TOTAL_SCANS = "stats:total_scans"
STATS_TOTAL_SCANS_TODAY = "stats:scans:today"
STATS_THREATS_BLOCKED = "stats:threats:blocked"
STATS_AVG_RISK_SCORE = "stats:avg_risk_score"
STATS_THREAT_DISTRIBUTION = "stats:threat_distribution"


@dataclass
class LiveStats:
    """Live statistics data structure."""
    scans_today: int = 0
    threats_blocked: int = 0
    avg_risk_score: float = 0.0
    scans_per_minute: float = 0.0
    active_connections: int = 0
    queue_length: int = 0
    threat_distribution: Dict[str, int] = field(default_factory=dict)
    recent_scans: List[Dict[str, Any]] = field(default_factory=list)
    last_updated: datetime = field(default_factory=datetime.utcnow)


class RealTimeStatsEngine:
    """
    Real-time statistics calculation engine.
    
    Provides:
    - Live scan counting
    - Running risk score averages
    - Threat distribution tracking
    - Recent scans buffer
    - Statistics broadcasting
    """
    
    def __init__(self, redis_client, database_session=None):
        self.redis = redis_client
        self.db = database_session
        self._update_task: Optional[asyncio.Task] = None
        self._running = False
        
        logger.info("RealTimeStatsEngine initialized")
    
    async def start(self):
        """Start the stats engine."""
        self._running = True
        self._update_task = asyncio.create_task(self._periodic_update())
        logger.info("RealTimeStatsEngine started")
    
    async def stop(self):
        """Stop the stats engine."""
        self._running = False
        if self._update_task:
            self._update_task.cancel()
            try:
                await self._update_task
            except asyncio.CancelledError:
                pass
        logger.info("RealTimeStatsEngine stopped")
    
    async def _periodic_update(self):
        """Periodic task to update statistics."""
        while self._running:
            try:
                await asyncio.sleep(60)  # Update every minute
                await self._update_derived_stats()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Periodic update error", error=str(e))
    
    async def _update_derived_stats(self):
        """Update derived statistics like scans per minute."""
        try:
            # Get scans in last minute
            key = "stats:scans:minute"
            scans_last_minute = await self.redis.get(key)
            scans_per_minute = float(scans_last_minute) if scans_last_minute else 0.0
            
            # Store in live stats
            await self.redis.hset(LIVE_STATS_KEY, "scans_per_minute", scans_per_minute)
            await self.redis.expire(LIVE_STATS_KEY, 3600)
            
        except Exception as e:
            logger.error("Error updating derived stats", error=str(e))
    
    # ─── Scan Tracking ───────────────────────────────────────────────────────
    
    async def increment_scan_count(self, scan_type: str = "url"):
        """Increment scan counter for real-time stats."""
        # Increment total scans
        await self.redis.incr(STATS_TOTAL_SCANS)
        await self.redis.incr(STATS_TOTAL_SCANS_TODAY)
        
        # Increment type-specific counter
        type_key = f"stats:scans:type:{scan_type}"
        await self.redis.incr(type_key)
        
        # Increment minute counter for rate calculation
        minute_key = "stats:scans:minute"
        await self.redis.incr(minute_key)
        await self.redis.expire(minute_key, 60)  # Expire after 1 minute
        
        # Set daily reset if needed
        today_key = f"stats:scans:date:{datetime.utcnow().strftime('%Y-%m-%d')}"
        await self.redis.set(today_key, 1, ex=86400)
        
        logger.debug("Scan count incremented", type=scan_type)
    
    async def increment_threat_count(self, threat_type: str = "phishing"):
        """Increment threat counter."""
        # Increment total threats blocked
        await self.redis.incr(STATS_THREATS_BLOCKED)
        
        # Increment type-specific
        type_key = f"stats:threats:type:{threat_type}"
        await self.redis.incr(type_key)
        
        # Update threat distribution
        dist_key = f"{STATS_THREAT_DISTRIBUTION}:{threat_type}"
        await self.redis.incr(dist_key)
        
        # Add to alerts list
        alert = {
            "type": threat_type,
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "high"
        }
        await self.redis.lpush(THREAT_ALERTS_KEY, json.dumps(alert))
        await self.redis.ltrim(THREAT_ALERTS_KEY, 0, 49)  # Keep last 50
        
        logger.debug("Threat count incremented", type=threat_type)
    
    async def update_risk_average(self, new_score: float):
        """Update running average of risk scores."""
        key = STATS_AVG_RISK_SCORE
        
        # Get current values
        current_avg = await self.redis.get(key)
        total_scans = await self.redis.get(STATS_TOTAL_SCANS)
        
        if current_avg and total_scans:
            current_avg = float(current_avg)
            total_scans = int(total_scans)
            new_avg = ((current_avg * total_scans) + new_score) / (total_scans + 1)
        else:
            new_avg = new_score
        
        await self.redis.set(key, str(new_avg))
        
        # Also store in hash for quick access
        await self.redis.hset(LIVE_STATS_KEY, "avg_risk_score", new_avg)
    
    async def add_recent_scan(self, scan_data: Dict[str, Any]):
        """Add scan to recent scans list."""
        scan_json = json.dumps({
            **scan_data,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        await self.redis.lpush(RECENT_SCANS_KEY, scan_json)
        await self.redis.ltrim(RECENT_SCANS_KEY, 0, 99)  # Keep last 100
    
    # ─── Getters ──────────────────────────────────────────────────────────────
    
    async def get_live_stats(self) -> LiveStats:
        """Get all live statistics for dashboard."""
        try:
            # Get basic stats
            scans_today = await self.redis.get(STATS_TOTAL_SCANS_TODAY) or 0
            threats_blocked = await self.redis.get(STATS_THREATS_BLOCKED) or 0
            avg_risk = await self.redis.get(STATS_AVG_RISK_SCORE) or 0
            scans_per_minute = await self.redis.get("stats:scans:minute") or 0
            
            # Get recent scans
            recent_scans_raw = await self.redis.lrange(RECENT_SCANS_KEY, 0, 9)
            recent_scans = [json.loads(s) for s in recent_scans_raw]
            
            # Get threat distribution
            threat_dist = {}
            threat_types = ["phishing", "malware", "spam", "defacement", "impersonation"]
            for threat_type in threat_types:
                count = await self.redis.get(f"{STATS_THREAT_DISTRIBUTION}:{threat_type}")
                if count:
                    threat_dist[threat_type] = int(count)
            
            return LiveStats(
                scans_today=int(scans_today),
                threats_blocked=int(threats_blocked),
                avg_risk_score=float(avg_risk),
                scans_per_minute=float(scans_per_minute),
                threat_distribution=threat_dist,
                recent_scans=recent_scans,
                last_updated=datetime.utcnow()
            )
            
        except Exception as e:
            logger.error("Error getting live stats", error=str(e))
            return LiveStats()
    
    async def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scans."""
        try:
            scans_raw = await self.redis.lrange(RECENT_SCANS_KEY, 0, limit - 1)
            return [json.loads(s) for s in scans_raw]
        except Exception as e:
            logger.error("Error getting recent scans", error=str(e))
            return []
    
    async def get_threat_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent threat alerts."""
        try:
            alerts_raw = await self.redis.lrange(THREAT_ALERTS_KEY, 0, limit - 1)
            return [json.loads(a) for a in alerts_raw]
        except Exception as e:
            logger.error("Error getting threat alerts", error=str(e))
            return []
    
    async def get_scan_rate(self, window_minutes: int = 5) -> float:
        """Calculate scans per minute over window."""
        try:
            # This would need a more sophisticated implementation
            # with time-bucketed counters in production
            current = await self.redis.get("stats:scans:minute") or 0
            return float(current)
        except Exception as e:
            logger.error("Error calculating scan rate", error=str(e))
            return 0.0
    
    # ─── Broadcast ──────────────────────────────────────────────────────────
    
    async def broadcast_update(self, ws_manager, event_type: str, data: dict):
        """Broadcast real-time update via WebSocket."""
        try:
            from app.services.websocket_manager import WebSocketMessage
            
            message = WebSocketMessage(
                event=event_type,
                data={
                    **data,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
            
            await ws_manager.broadcast(message, "stats")
            
        except Exception as e:
            logger.error("Error broadcasting update", error=str(e))
    
    async def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get complete dashboard summary."""
        stats = await self.get_live_stats()
        
        return {
            "overview": {
                "total_scans_today": stats.scans_today,
                "threats_detected_today": stats.threats_blocked,
                "avg_risk_score": round(stats.avg_risk_score, 3),
                "scans_per_minute": round(stats.scans_per_minute, 2),
                "active_connections": stats.active_connections,
                "queue_length": stats.queue_length
            },
            "threat_distribution": stats.threat_distribution,
            "recent_scans": stats.recent_scans[:10],
            "last_updated": stats.last_updated.isoformat()
        }


# Global stats engine instance
stats_engine: Optional[RealTimeStatsEngine] = None


async def get_stats_engine(redis_client=None) -> RealTimeStatsEngine:
    """Get or create the stats engine."""
    global stats_engine
    
    if stats_engine is None:
        if redis_client is None:
            from app.services.redis import get_redis_client
            redis_client = await get_redis_client()
        
        stats_engine = RealTimeStatsEngine(redis_client)
        await stats_engine.start()
    
    return stats_engine


# ─── Redis Data Structures Helper ──────────────────────────────────────────

class RedisDataStructures:
    """Helper class for Redis data structures."""
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    # Scan Queue Operations
    async def add_to_scan_queue(self, scan_data: dict):
        """Add scan to processing queue."""
        await self.redis.lpush(SCAN_QUEUE_KEY, json.dumps(scan_data))
    
    async def get_scan_from_queue(self) -> Optional[dict]:
        """Get next scan from queue (blocking)."""
        result = await self.redis.brpop(SCAN_QUEUE_KEY, timeout=5)
        if result:
            return json.loads(result[1])
        return None
    
    async def get_queue_length(self) -> int:
        """Get current queue length."""
        return await self.redis.llen(SCAN_QUEUE_KEY)
    
    # Recent Scans (List with max size)
    async def add_recent_scan(self, scan_data: dict):
        """Add scan to recent list."""
        await self.redis.lpush(RECENT_SCANS_KEY, json.dumps(scan_data))
        await self.redis.ltrim(RECENT_SCANS_KEY, 0, 99)
    
    async def get_recent_scans(self, count: int = 10) -> List[dict]:
        """Get recent scans."""
        results = await self.redis.lrange(RECENT_SCANS_KEY, 0, count - 1)
        return [json.loads(r) for r in results]
    
    # Live Stats (Hash)
    async def update_live_stat(self, key: str, value: any):
        """Update a live stat field."""
        await self.redis.hset(LIVE_STATS_KEY, key, json.dumps(value) if isinstance(value, (dict, list)) else value)
    
    async def get_live_stat(self, key: str) -> any:
        """Get a live stat field."""
        value = await self.redis.hget(LIVE_STATS_KEY, key)
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return None
    
    async def get_all_live_stats(self) -> dict:
        """Get all live stats."""
        return await self.redis.hgetall(LIVE_STATS_KEY)
    
    # Threat Alerts (List with max size)
    async def add_threat_alert(self, alert: dict):
        """Add threat alert."""
        await self.redis.lpush(THREAT_ALERTS_KEY, json.dumps(alert))
        await self.redis.ltrim(THREAT_ALERTS_KEY, 0, 49)
    
    async def get_threat_alerts(self, count: int = 10) -> List[dict]:
        """Get threat alerts."""
        results = await self.redis.lrange(THREAT_ALERTS_KEY, 0, count - 1)
        return [json.loads(r) for r in results]
    
    # Active Connections (Set)
    async def add_connection(self, connection_id: str):
        """Add active connection."""
        await self.redis.sadd(ACTIVE_CONNECTIONS_KEY, connection_id)
    
    async def remove_connection(self, connection_id: str):
        """Remove active connection."""
        await self.redis.srem(ACTIVE_CONNECTIONS_KEY, connection_id)
    
    async def get_active_connections_count(self) -> int:
        """Get count of active connections."""
        return await self.redis.scard(ACTIVE_CONNECTIONS_KEY)
    
    # Scan Results Cache
    async def cache_scan_result(self, scan_id: str, result: dict, ttl: int = 3600):
        """Cache scan result."""
        key = SCAN_RESULTS_KEY.format(scan_id=scan_id)
        await self.redis.setex(key, ttl, json.dumps(result))
    
    async def get_cached_scan_result(self, scan_id: str) -> Optional[dict]:
        """Get cached scan result."""
        key = SCAN_RESULTS_KEY.format(scan_id=scan_id)
        result = await self.redis.get(key)
        if result:
            return json.loads(result)
        return None


async def get_redis_structures() -> RedisDataStructures:
    """Get Redis data structures helper."""
    from app.services.redis import get_redis_client
    redis_client = await get_redis_client()
    return RedisDataStructures(redis_client)
