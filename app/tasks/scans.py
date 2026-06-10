"""Celery tasks for durable asynchronous scan processing."""
import asyncio

import structlog
from celery import Task

from app.tasks.celery_app import celery_app

logger = structlog.get_logger(__name__)
_worker_loop = None


def _run_async(coro):
    global _worker_loop
    if _worker_loop is None or _worker_loop.is_closed():
        _worker_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_worker_loop)
    return _worker_loop.run_until_complete(coro)


class ScanTask(Task):
    """Celery task hooks that make retries and terminal failures visible."""

    def before_start(self, task_id, args, kwargs):
        logger.info("Celery scan task starting", task_id=task_id, scan_id=args[0])

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        logger.warning(
            "Celery scan task retrying",
            task_id=task_id,
            scan_id=args[0],
            error=str(exc),
        )

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        from app.services.scan_processing import mark_scan_processing_failure

        scan_id = args[0]
        logger.error(
            "Celery scan task permanently failed",
            task_id=task_id,
            scan_id=scan_id,
            error=str(exc),
        )
        try:
            _run_async(mark_scan_processing_failure(scan_id, str(exc)))
        except Exception as status_exc:
            logger.exception(
                "Could not persist terminal scan failure",
                scan_id=scan_id,
                error=str(status_exc),
            )


@celery_app.task(
    bind=True,
    base=ScanTask,
    name="app.tasks.scans.process_scan",
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 3},
)
def process_scan_task(self, scan_id: str):
    """Initialize worker dependencies and process one persisted scan."""
    logger.info("Celery scan task received", scan_id=scan_id, task_id=self.request.id)

    async def run():
        from app.services import database as db_service
        from app.services.redis import get_redis_client
        from app.services.scan_processing import process_scan
        from app.services.threat_graph_engine import init_threat_engine

        logger.info("Initializing scan worker dependencies", scan_id=scan_id)
        if db_service.async_session_maker is None:
            await db_service.init_db()
        redis = await get_redis_client()
        await init_threat_engine(db_service.db_pool, redis)
        return await process_scan(scan_id)

    return _run_async(run())
