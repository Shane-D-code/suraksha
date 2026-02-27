"""
Redis service for caching operations.
"""
from typing import Optional, Any
import json
import redis.asyncio as redis
import structlog

from app.config import settings

logger = structlog.get_logger(__name__)

# Global Redis clients
redis_client = None
raw_redis_client = None


async def init_redis():
    """Initialize Redis connections."""
    global redis_client, raw_redis_client
    
    redis_client = redis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
    )
    
    raw_redis_client = redis.from_url(
        settings.REDIS_URL,
        decode_responses=False,
    )
    
    # Test connections
    await redis_client.ping()
    await raw_redis_client.ping()
    logger.info("Redis initialized", url=settings.REDIS_URL)


async def close_redis():
    """Close Redis connection."""
    global redis_client
    if redis_client:
        await redis_client.close()
        logger.info("Redis connection closed")


async def get_redis_client() -> redis.Redis:
    """Get Redis client instance (decoded)."""
    global redis_client
    if redis_client is None:
        await init_redis()
    return redis_client


async def get_raw_redis_client() -> redis.Redis:
    """Get raw Redis client instance (binary)."""
    global raw_redis_client
    if raw_redis_client is None:
        await init_redis()
    return raw_redis_client


async def get_cache(key: str) -> Optional[Any]:
    """Get value from cache."""
    client = await get_redis_client()
    value = await client.get(key)
    if value:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return None


async def set_cache(key: str, value: Any, ttl: Optional[int] = None):
    """Set value in cache with optional TTL."""
    client = await get_redis_client()
    if ttl is None:
        ttl = settings.REDIS_CACHE_TTL
    
    if isinstance(value, (dict, list)):
        value = json.dumps(value)
    
    await client.setex(key, ttl, value)


async def delete_cache(key: str):
    """Delete value from cache."""
    client = await get_redis_client()
    await client.delete(key)


async def get_cache_ttl(key: str) -> int:
    """Get TTL for a key."""
    client = await get_redis_client()
    return await client.ttl(key)


async def check_redis_health() -> bool:
    """Check if Redis is healthy."""
    try:
        client = await get_redis_client()
        await client.ping()
        return True
    except Exception as e:
        logger.error("Redis health check failed", error=str(e))
        return False
