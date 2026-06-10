"""Durable lifecycle and background processing for asynchronous scans."""
import json
import hashlib
import time
from datetime import datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.db import RiskLevelEnum, Scan as DBScan

logger = structlog.get_logger(__name__)

REDIS_EVENTS_CHANNEL = "phishguard:scan_events"


def _scan_status(scan: DBScan) -> str:
    return (scan.meta or {}).get("status", "completed")


def scan_to_detail(scan: DBScan) -> dict[str, Any]:
    """Convert the durable scan row into the plural scan API contract."""
    meta = scan.meta or {}
    return {
        "scan_id": scan.scan_id,
        "url": scan.url,
        "scan_type": meta.get("scan_type", "url"),
        "status": _scan_status(scan),
        "risk_score": float(meta.get("risk_score", max(scan.graph_score, scan.model_score))),
        "threat_level": meta.get("threat_level", scan.risk.value.lower()),
        "created_at": scan.created_at.isoformat(),
        "completed_at": meta.get("completed_at"),
        "processing_time_ms": meta.get("processing_time_ms"),
        "results": meta.get("results", []),
        "threats": meta.get("threats", []),
    }


def scan_to_recent(scan: DBScan) -> dict[str, Any]:
    detail = scan_to_detail(scan)
    return {
        "scan_id": detail["scan_id"],
        "url": detail["url"] or "text scan",
        "scan_type": detail["scan_type"],
        "status": detail["status"],
        "risk_score": detail["risk_score"],
        "threat_level": detail["threat_level"],
        "created_at": detail["created_at"],
    }


async def create_pending_scan(
    session: AsyncSession, scan_id: str, request: Any, created_at: datetime
) -> DBScan:
    """Insert and commit a pending scan before it is sent to the worker."""
    input_hash = hashlib.sha256(request.model_dump_json(exclude_none=True).encode()).hexdigest()
    scan = DBScan(
        scan_id=scan_id,
        input_hash=input_hash,
        text=request.text,
        url=request.url,
        html=request.html,
        risk=RiskLevelEnum.LOW,
        confidence=0.0,
        graph_score=0.0,
        model_score=0.0,
        reasons=[],
        meta={
            **request.metadata,
            "status": "pending",
            "scan_type": request.scan_type,
            "source": request.source,
            "user_id": request.user_id,
            "risk_score": 0.0,
            "threat_level": "low",
            "results": [],
            "threats": [],
        },
        created_at=created_at,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    logger.info("Scan persistence succeeded", scan_id=scan_id, status="pending")
    return scan


async def mark_scan_queue_failure(session: AsyncSession, scan_id: str, error: str) -> None:
    scan = await session.scalar(select(DBScan).where(DBScan.scan_id == scan_id))
    if not scan:
        return
    scan.meta = {**(scan.meta or {}), "status": "failed", "error": error}
    await session.commit()
    logger.error("Scan queue dispatch failed", scan_id=scan_id, error=error)


async def mark_scan_queued(
    session: AsyncSession, scan_id: str, task_id: str, queue: str
) -> None:
    """Persist Celery dispatch metadata after the broker accepts the task."""
    scan = await session.scalar(select(DBScan).where(DBScan.scan_id == scan_id))
    if not scan:
        raise LookupError(f"Scan {scan_id} disappeared before queue dispatch was recorded")
    scan.meta = {
        **(scan.meta or {}),
        "status": "pending",
        "task_id": task_id,
        "queue": queue,
        "queued_at": datetime.utcnow().isoformat(),
    }
    await session.commit()
    logger.info("Scan queue dispatch persisted", scan_id=scan_id, task_id=task_id, queue=queue)


async def mark_scan_processing_failure(scan_id: str, error: str) -> None:
    """Persist a terminal worker failure so clients do not poll forever."""
    from app.services import database as db_service

    if db_service.async_session_maker is None:
        await db_service.init_db()
    async with db_service.async_session_maker() as session:
        scan = await session.scalar(select(DBScan).where(DBScan.scan_id == scan_id))
        if not scan:
            return
        scan.meta = {**(scan.meta or {}), "status": "failed", "error": error}
        await session.commit()
    await _publish_scan_event("scan:failed", scan_id, {"error": error})
    logger.error("Scan processing failed", scan_id=scan_id, error=error)


async def _publish_scan_event(event_type: str, scan_id: str, data: dict | None = None) -> None:
    """Publish scan lifecycle event to Redis Pub/Sub for WebSocket broadcasting."""
    try:
        from app.services.redis import get_redis_client
        print("PUBLISH REDIS URL:", settings.REDIS_URL)
        redis = await get_redis_client()
        print("PUBLISH REDIS CLIENT:", redis)
        payload = json.dumps({
            "event": event_type,
            "scan_id": scan_id,
            "data": data or {},
            "timestamp": datetime.utcnow().isoformat(),
        })
        result = await redis.publish(REDIS_EVENTS_CHANNEL, payload)
        print("PUBLISH_RESULT:", result, "EVENT:", event_type)
        logger.info("WS broadcast queued", event_type=event_type, scan_id=scan_id, num_subscribers=result)
    except Exception as e:
        logger.warning("Failed to publish scan event",
                       event_type=event_type, scan_id=scan_id, error=str(e))


async def process_scan(scan_id: str) -> dict[str, Any]:
    """Process a previously persisted scan and commit its final result."""
    from app.api.routes import get_ml_score
    from app.services import database as db_service
    from app.services.realtime_stats_engine import get_stats_engine, get_redis_structures
    from app.services.threat_graph_engine import get_threat_engine

    started = time.monotonic()
    logger.info("Scan processing started", scan_id=scan_id)

    async with db_service.async_session_maker() as session:
        scan = await session.scalar(select(DBScan).where(DBScan.scan_id == scan_id))
        if not scan:
            raise LookupError(f"Scan {scan_id} not found")

        scan.meta = {**(scan.meta or {}), "status": "processing"}
        await session.commit()
        logger.info("Scan status updated", scan_id=scan_id, status="processing")
        await _publish_scan_event("scan:processing", scan_id)

        graph_score = 0.0
        reasons: list[str] = []
        if scan.url:
            graph_result = await (await get_threat_engine()).analyze(scan.url, scan.text, scan.html)
            graph_score = float(graph_result.gnn_score)
            reasons.extend(graph_result.reasons)

        content = scan.text or scan.url or scan.html or ""
        model_score = float(await get_ml_score(content, scan.url, scan.html))
        risk_score = min((graph_score * settings.GRAPH_WEIGHT) + (model_score * settings.MODEL_WEIGHT), 1.0)
        risk = RiskLevelEnum.HIGH if risk_score >= 0.7 else RiskLevelEnum.MEDIUM if risk_score >= 0.4 else RiskLevelEnum.LOW
        completed_at = datetime.utcnow()
        processing_time_ms = round((time.monotonic() - started) * 1000)
        results = [
            {"component": "graph", "score": graph_score},
            {"component": "model", "score": model_score},
        ]
        threats = (
            [{"type": "phishing", "severity": risk.value.lower(), "reasons": reasons}]
            if risk == RiskLevelEnum.HIGH
            else []
        )

        scan.risk = risk
        scan.confidence = risk_score
        scan.graph_score = graph_score
        scan.model_score = model_score
        scan.reasons = reasons
        scan.meta = {
            **(scan.meta or {}),
            "status": "completed",
            "risk_score": risk_score,
            "threat_level": risk.value.lower(),
            "completed_at": completed_at.isoformat(),
            "processing_time_ms": processing_time_ms,
            "results": results,
            "threats": threats,
        }
        await session.commit()
        await session.refresh(scan)
        detail = scan_to_detail(scan)
        logger.info("Scan results persisted", scan_id=scan_id, status="completed")

    # Broadcast scan completed event
    await _publish_scan_event("scan:completed", scan_id, {
        "risk_score": risk_score,
        "threat_level": risk.value.lower(),
        "processing_time_ms": processing_time_ms,
        "results": results,
        "threats": threats,
    })

    redis_structs = await get_redis_structures()
    await redis_structs.cache_scan_result(scan_id, detail)
    stats = await get_stats_engine()
    await stats.add_recent_scan(scan_to_recent(scan))
    await stats.update_risk_average(risk_score)
    if risk == RiskLevelEnum.HIGH:
        await stats.increment_threat_count("phishing")
        if threats:
            for threat in threats:
                await _publish_scan_event("threat:detected", scan_id, threat)

    logger.info(
        "Scan processing completed",
        scan_id=scan_id,
        risk=risk.value,
        processing_time_ms=processing_time_ms,
    )
    return detail
