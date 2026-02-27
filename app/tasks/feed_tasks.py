"""
Periodic tasks for updating threat feeds.
"""
import asyncio
from datetime import datetime
from urllib.parse import urlparse
import structlog

from app.tasks.celery_app import celery_app
from app.services.threat_feeds import fetch_all_threat_feeds, get_feed_aggregator, sync_feeds_to_graph
from app.services.database import async_session_maker
from app.models.threat_indicator import ThreatIndicator

logger = structlog.get_logger(__name__)


def _extract_domain(value: str, indicator_type: str) -> str:
    """Extract domain from URL or return the value as-is."""
    if indicator_type == "url" and value:
        try:
            parsed = urlparse(value if value.startswith("http") else f"http://{value}")
            return parsed.netloc or parsed.path
        except Exception:
            return value
    return value


async def _persist_indicators_to_db(indicators: list) -> int:
    """
    Persist threat indicators to the database.
    Returns the number of indicators persisted.
    """
    if not indicators:
        return 0
    
    persisted = 0
    
    async with async_session_maker() as session:
        for indicator in indicators:
            try:
                # Extract domain from URL
                domain = _extract_domain(
                    indicator.get("value", ""),
                    indicator.get("type", "domain")
                )
                
                # Check if already exists
                from sqlalchemy import select, and_
                stmt = select(ThreatIndicator).where(
                    and_(
                        ThreatIndicator.value == indicator.get("value"),
                        ThreatIndicator.source == indicator.get("source")
                    )
                )
                result = await session.execute(stmt)
                existing = result.scalar_one_or_none()
                
                if existing:
                    # Update existing
                    existing.risk_score = indicator.get("confidence", 0.8)
                    existing.last_updated = datetime.utcnow()
                    existing.extra_data = indicator.get("metadata", {})
                else:
                    # Create new
                    db_indicator = ThreatIndicator(
                        value=indicator.get("value"),
                        domain=domain,
                        indicator_type=indicator.get("type", "domain"),
                        risk_score=indicator.get("confidence", 0.8),
                        threat_type="phishing",
                        source=indicator.get("source", "external_feed"),
                        first_seen=datetime.utcnow(),
                        tags=[indicator.get("source", "external")],
                        extra_data=indicator.get("metadata", {})
                    )
                    session.add(db_indicator)
                
                persisted += 1
                
            except Exception as e:
                logger.debug(f"Failed to persist indicator: {e}")
        
        await session.commit()
    
    return persisted


@celery_app.task(bind=True, name="app.tasks.feed_tasks.update_threat_feeds_task")
def update_threat_feeds_task(self):
    """
    Periodic task to update threat graph from external feeds.
    Runs every hour via Celery Beat.
    """
    logger.info("Starting threat feed update task")
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        # Fetch all threat feeds
        threats = loop.run_until_complete(fetch_all_threat_feeds())
        
        # Persist to database
        persisted = loop.run_until_complete(_persist_indicators_to_db(threats))
        
        # Sync to graph (Redis cache)
        from app.services.redis import get_redis_client
        redis_client = loop.run_until_complete(get_redis_client())
        if redis_client:
            loop.run_until_complete(sync_feeds_to_graph(redis_client=redis_client))
        
        # Get feed status
        aggregator = get_feed_aggregator()
        feed_status = aggregator.get_status()
        
        logger.info(
            "Threat feed update complete",
            threats_fetched=len(threats),
            threats_persisted=persisted,
            feeds=[f['name'] for f in feed_status]
        )
        
        return {
            "status": "success",
            "threats_updated": persisted,
            "feeds": feed_status
        }
    except Exception as e:
        logger.error("Threat feed update failed", error=str(e))
        return {
            "status": "error",
            "message": str(e)
        }
    finally:
        loop.close()


@celery_app.task(bind=True, name="app.tasks.feed_tasks.get_feed_status_task")
def get_feed_status_task(self):
    """
    Get status of all configured threat feeds.
    """
    try:
        aggregator = get_feed_aggregator()
        status = aggregator.get_status()
        return {
            "status": "success",
            "feeds": status
        }
    except Exception as e:
        logger.error("Feed status check failed", error=str(e))
        return {
            "status": "error",
            "message": str(e)
        }
