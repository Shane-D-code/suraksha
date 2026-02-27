"""
Periodic maintenance tasks.
"""
import asyncio
from datetime import datetime, timedelta
import structlog

from app.tasks.celery_app import celery_app
from app.config import settings

logger = structlog.get_logger(__name__)


@celery_app.task(bind=True, name="app.tasks.maintenance.cleanup_old_scans")
def cleanup_old_scans(self, days: int = 90):
    """
    Remove scans older than retention period.
    Runs weekly (Sunday 3 AM) via Celery Beat.
    
    Args:
        days: Number of days to keep (default: 90)
    """
    logger.info("Starting old scans cleanup", days=days)
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        from sqlalchemy import delete
        from app.services.database import async_session_maker
        from app.models.db import Scan
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        async def cleanup():
            async with async_session_maker() as session:
                result = await session.execute(
                    delete(Scan).where(Scan.created_at < cutoff_date)
                )
                await session.commit()
                return result.rowcount
        
        deleted = loop.run_until_complete(cleanup())
        
        logger.info("Old scans cleanup complete", deleted=deleted)
        
        return {
            "status": "success",
            "deleted_count": deleted,
            "cutoff_date": cutoff_date.isoformat()
        }
    except Exception as e:
        logger.error("Old scans cleanup failed", error=str(e))
        return {
            "status": "error",
            "message": str(e)
        }
    finally:
        loop.close()


@celery_app.task(bind=True, name="app.tasks.maintenance.cleanup_old_feedback")
def cleanup_old_feedback(self, days: int = 180):
    """
    Remove old feedback entries.
    Keeps feedback for learning purposes longer than scans.
    
    Args:
        days: Number of days to keep (default: 180)
    """
    logger.info("Starting old feedback cleanup", days=days)
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        from sqlalchemy import delete
        from app.services.database import async_session_maker
        from app.models.db import Feedback
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        async def cleanup():
            async with async_session_maker() as session:
                result = await session.execute(
                    delete(Feedback).where(Feedback.created_at < cutoff_date)
                )
                await session.commit()
                return result.rowcount
        
        deleted = loop.run_until_complete(cleanup())
        
        logger.info("Old feedback cleanup complete", deleted=deleted)
        
        return {
            "status": "success",
            "deleted_count": deleted,
            "cutoff_date": cutoff_date.isoformat()
        }
    except Exception as e:
        logger.error("Old feedback cleanup failed", error=str(e))
        return {
            "status": "error",
            "message": str(e)
        }
    finally:
        loop.close()


@celery_app.task(bind=True, name="app.tasks.maintenance.clear_cache")
def clear_cache(self):
    """
    Clear Redis cache for fresh data.
    """
    logger.info("Starting cache clear")
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        from app.services.redis import get_redis_client
        
        async def clear():
            client = await get_redis_client()
            # Clear specific keys pattern
            keys_to_clear = [
                "graph:data",
                "embedding:*",
                "similarity:*"
            ]
            
            total_cleared = 0
            for pattern in keys_to_clear:
                if "*" in pattern:
                    keys = await client.keys(pattern)
                    if keys:
                        await client.delete(*keys)
                        total_cleared += len(keys)
                else:
                    await client.delete(pattern)
                    total_cleared += 1
            
            return total_cleared
        
        cleared = loop.run_until_complete(clear())
        
        logger.info("Cache clear complete", keys_cleared=cleared)
        
        return {
            "status": "success",
            "keys_cleared": cleared
        }
    except Exception as e:
        logger.error("Cache clear failed", error=str(e))
        return {
            "status": "error",
            "message": str(e)
        }
    finally:
        loop.close()
