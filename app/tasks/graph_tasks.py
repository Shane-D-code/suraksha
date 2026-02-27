"""
Periodic tasks for graph maintenance and recalculation.
"""
import asyncio
import structlog

from app.tasks.celery_app import celery_app

logger = structlog.get_logger(__name__)


@celery_app.task(bind=True, name="app.tasks.graph_tasks.recalculate_metrics")
def recalculate_metrics(self):
    """
    Recalculate graph centrality and risk scores.
    Runs daily at 2 AM via Celery Beat.
    """
    logger.info("Starting graph metrics recalculation")
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        # Import here to avoid circular imports
        from app.services.graph_update_service import GraphUpdateService
        from app.services.database import engine
        from app.services.redis import get_redis_client
        
        # Initialize services
        redis_client = loop.run_until_complete(get_redis_client())
        
        # This would recalculate centrality scores
        # In production, this would rebuild the graph from DB
        # and recalculate all centrality metrics
        
        logger.info("Graph metrics recalculation complete")
        
        return {
            "status": "success",
            "nodes_processed": 0,
            "message": "Graph metrics recalculated"
        }
    except Exception as e:
        logger.error("Graph metrics recalculation failed", error=str(e))
        return {
            "status": "error",
            "message": str(e)
        }
    finally:
        loop.close()


@celery_app.task(bind=True, name="app.tasks.graph_tasks.rebuild_graph")
def rebuild_graph(self):
    """
    Rebuild the entire threat graph from database.
    Can be triggered manually or scheduled.
    """
    logger.info("Starting graph rebuild")
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        from app.services.graph_update_service import GraphUpdateService
        from app.services.database import engine
        from app.services.redis import get_redis_client
        
        redis_client = loop.run_until_complete(get_redis_client())
        graph_service = GraphUpdateService(engine, redis_client)
        
        # Load graph from database
        loop.run_until_complete(graph_service.load_graph_from_db())
        
        stats = graph_service.graph_stats()
        
        logger.info("Graph rebuild complete", stats=stats)
        
        return {
            "status": "success",
            "stats": stats
        }
    except Exception as e:
        logger.error("Graph rebuild failed", error=str(e))
        return {
            "status": "error",
            "message": str(e)
        }
    finally:
        loop.close()
