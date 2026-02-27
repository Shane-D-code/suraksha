"""
Celery application configuration with Beat scheduler.
"""
from celery import Celery
from celery.schedules import crontab
import structlog

from app.config import settings

logger = structlog.get_logger(__name__)

# Create Celery app
celery_app = Celery(
    "threat_intel_tasks",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.ingestion",
        "app.tasks.feed_tasks",
        "app.tasks.graph_tasks",
        "app.tasks.maintenance",
    ],
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour
    task_soft_time_limit=3000,  # 50 minutes
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=1000,
    result_expires=3600,  # Results expire after 1 hour
    task_acks_late=True,  # Acknowledge task after completion
    task_reject_on_worker_lost=True,  # Requeue if worker dies
)

# Celery Beat Schedule Configuration
celery_app.conf.beat_schedule = {
    # Update threat feeds every hour
    "update-threat-feeds-hourly": {
        "task": "app.tasks.feed_tasks.update_threat_feeds_task",
        "schedule": 3600.0,  # Every hour
        "options": {"queue": "threat_intel"}
    },
    # Ingest external IOC feeds every 6 hours
    "ingest-ioc-feeds": {
        "task": "app.tasks.ingestion.ingest_external_feeds",
        "schedule": 21600.0,  # Every 6 hours
        "options": {"queue": "ingestion"}
    },
    # Recalculate graph metrics daily at 2 AM
    "recalculate-graph-metrics": {
        "task": "app.tasks.graph_tasks.recalculate_metrics",
        "schedule": crontab(hour=2, minute=0),
        "options": {"queue": "graph"}
    },
    # Cleanup old scans weekly (Sunday 3 AM)
    "cleanup-old-scans": {
        "task": "app.tasks.maintenance.cleanup_old_scans",
        "schedule": crontab(hour=3, minute=0, day_of_week=0),
        "options": {"queue": "maintenance"}
    },
    # Health check every 5 minutes
    "celery-health-check": {
        "task": "app.tasks.celery_app.health_check",
        "schedule": 300.0,  # Every 5 minutes
    },
}


@celery_app.task(bind=True, name="health_check")
def health_check(self):
    """Health check task."""
    return {"status": "healthy", "timestamp": str(self.request.id)}


@celery_app.task(bind=True, name="test_task")
def test_task(self, *args, **kwargs):
    """Test task for verification."""
    logger.info("Test task executed", args=args, kwargs=kwargs)
    return {"result": "success"}
