"""
Threat data ingestion tasks for Celery.
"""
import hashlib
import aiohttp
from datetime import datetime
from celery import Task
import structlog

from app.tasks.celery_app import celery_app
from app.config import settings

logger = structlog.get_logger(__name__)


class IngestionTask(Task):
    """Base class for ingestion tasks with error handling."""
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure."""
        logger.error(
            "Ingestion task failed",
            task_id=task_id,
            error=str(exc),
            args=args,
        )
        super().on_failure(exc, task_id, args, kwargs, einfo)


@celery_app.task(bind=True, base=IngestionTask, name="ingest_feed")
def ingest_feed(self, feed_url: str, feed_type: str = "PHISHING"):
    """
    Ingest threat data from a feed.
    
    Args:
        feed_url: URL of the threat feed
        feed_type: Type of threat (PHISHING, MALWARE, etc.)
    """
    logger.info("Starting feed ingestion", feed_url=feed_url, feed_type=feed_type)
    
    # Fetch feed data
    import asyncio
    
    async def fetch_and_process():
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(feed_url, timeout=30) as response:
                    if response.status != 200:
                        logger.error(
                            "Feed fetch failed",
                            feed_url=feed_url,
                            status=response.status,
                        )
                        return {"status": "failed", "reason": "HTTP error"}
                    
                    data = await response.text()
                    
                    # Process feed data (implement specific parser based on feed format)
                    processed = process_feed_data(data, feed_type)
                    
                    # Deduplicate and store
                    stored_count = await store_threat_data(processed)
                    
                    return {
                        "status": "success",
                        "feed_url": feed_url,
                        "processed": len(processed),
                        "stored": stored_count,
                    }
            except Exception as e:
                logger.error("Feed ingestion error", feed_url=feed_url, error=str(e))
                return {"status": "failed", "reason": str(e)}
    
    # Run async function
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(fetch_and_process())
    loop.close()
    
    return result


def process_feed_data(data: str, feed_type: str):
    """
    Process raw feed data into structured format.
    
    Args:
        data: Raw feed data
        feed_type: Type of feed
    
    Returns:
        List of processed threat entries
    """
    processed = []
    
    # This is a simplified implementation
    # In production, implement specific parsers for each feed format
    lines = data.strip().split("\n")
    
    for line in lines:
        if not line or line.startswith("#"):
            continue
        
        # Basic processing - extract domain/URL
        entry = {
            "value": line.strip(),
            "type": feed_type,
            "source": "feed",
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        # Generate hash for deduplication
        entry["hash"] = hashlib.sha256(
            f"{entry['value']}:{entry['type']}".encode()
        ).hexdigest()
        
        processed.append(entry)
    
    return processed


async def store_threat_data(threats: list) -> int:
    """
    Store threat data in database with deduplication.
    
    Args:
        threats: List of threat entries
    
    Returns:
        Number of entries stored
    """
    # This would use SQLAlchemy to insert into the database
    # Skip duplicates based on hash
    stored_count = 0
    
    for threat in threats:
        # Check if hash exists in database
        # If not, insert
        # For MVP, just count
        stored_count += 1
    
    logger.info("Threat data stored", count=stored_count)
    return stored_count


@celery_app.task(bind=True, name="update_graph")
def update_graph(self):
    """
    Update the threat graph with latest data.
    """
    logger.info("Starting graph update")
    
    # This would:
    # 1. Query latest domain/relation data from database
    # 2. Rebuild or update the graph
    # 3. Recalculate centrality scores
    # 4. Cache the updated graph
    
    return {"status": "success", "nodes_updated": 0}


@celery_app.task(bind=True, name="recalculate_scores")
def recalculate_scores(self):
    """
    Recalculate risk scores for all domains.
    """
    logger.info("Starting score recalculation")
    
    # This would:
    # 1. Fetch all domains from database
    # 2. Recalculate scores using graph and ML
    # 3. Update database with new scores
    
    return {"status": "success", "scores_updated": 0}


@celery_app.task(bind=True, name="cleanup_old_scans")
def cleanup_old_scans(self, days: int = 90):
    """
    Clean up old scan records.
    
    Args:
        days: Number of days to keep
    """
    logger.info("Starting scan cleanup", days=days)
    
    # This would delete scans older than specified days
    # Keep feedback for learning
    
    return {"status": "success", "deleted": 0}


@celery_app.task(bind=True, name="ingest_external_feeds")
def ingest_external_feeds(self):
    """
    Ingest external IOC (Indicator of Compromise) feeds.
    Runs every 6 hours via Celery Beat.
    
    This task fetches threat data from multiple external sources
    and stores them in the database for real-time checking.
    """
    logger.info("Starting external IOC feed ingestion")
    
    import asyncio
    
    async def fetch_and_store():
        from app.services.threat_feeds import fetch_all_threat_feeds
        from app.services.database import async_session_maker
        from app.models.threat_indicator import ThreatIndicator
        
        # Fetch from all feeds
        threats = await fetch_all_threat_feeds()
        
        if not threats:
            logger.warning("No threats fetched from feeds")
            return {"status": "success", "processed": 0, "stored": 0}
        
        # Store in database
        stored_count = 0
        async with async_session_maker() as session:
            for threat in threats:
                try:
                    indicator = ThreatIndicator(
                        domain=threat.get('domain'),
                        indicator_type=threat.get('type', 'domain'),
                        risk_score=threat.get('confidence', 0.8),
                        threat_type='phishing',
                        source=threat.get('source', 'external_feed'),
                        first_seen=threat.get('first_seen'),
                        tags=[threat.get('source', 'external')]
                    )
                    session.add(indicator)
                    stored_count += 1
                except Exception as e:
                    logger.debug(f"Failed to add threat: {e}")
            
            await session.commit()
        
        logger.info("External IOC feed ingestion complete", stored=stored_count)
        return {"status": "success", "processed": len(threats), "stored": stored_count}
    
    # Run async function
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(fetch_and_store())
    loop.close()
    
    return result
