"""
Real-Time Dashboard API Routes

Provides:
- Scan management with real-time status updates
- Dashboard statistics endpoints
- Chart data endpoints
- Real-time event streaming
"""
import uuid
import time
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import structlog

from app.services.redis import get_redis_client
from app.services.websocket_manager import (
    ws_manager, 
    websocket_endpoint, 
    WebSocketMessage,
    WebSocketEventType
)
from app.services.realtime_stats_engine import (
    get_stats_engine, 
    RealTimeStatsEngine,
    RedisDataStructures,
    get_redis_structures
)
from app.services.database import get_db_session

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["Real-Time Dashboard"])


# ─── Request/Response Models ────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Scan request model."""
    url: Optional[str] = None
    text: Optional[str] = None
    html: Optional[str] = None
    scan_type: str = "url"
    source: str = "api"
    metadata: dict = {}
    user_id: Optional[str] = None


class ScanResponse(BaseModel):
    """Scan response model."""
    scan_id: str
    status: str
    estimated_time: Optional[int] = 5
    created_at: datetime


class ScanDetailResponse(BaseModel):
    """Scan detail response."""
    scan_id: str
    url: Optional[str]
    scan_type: str
    status: str
    risk_score: float
    threat_level: str
    created_at: datetime
    completed_at: Optional[datetime]
    processing_time_ms: Optional[int]
    results: List[dict] = []
    threats: List[dict] = []


class DashboardStatsResponse(BaseModel):
    """Dashboard statistics response."""
    total_scans_today: int
    threats_detected_today: int
    avg_risk_score: float
    scans_per_minute: float
    active_connections: int
    queue_length: int
    threat_distribution: dict


class ChartDataResponse(BaseModel):
    """Chart data response."""
    labels: List[str]
    datasets: List[dict]
    options: dict = {}


class RecentScansResponse(BaseModel):
    """Recent scans response."""
    scans: List[dict]
    total: int


class ActiveThreatsResponse(BaseModel):
    """Active threats response."""
    threats: List[dict]
    total_count: int


class WebSocketTokenResponse(BaseModel):
    """WebSocket token response."""
    token: str
    expires_in: int


class AlertConfigRequest(BaseModel):
    """Alert configuration request."""
    alert_types: List[str] = []
    notification_channels: List[str] = []
    thresholds: dict = {}


# ─── Scan Management Endpoints ─────────────────────────────────────────────

@router.post("/scans", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(request: ScanRequest):
    """
    Create a new scan request.
    
    Returns scan_id immediately - scan processing happens asynchronously.
    """
    scan_id = str(uuid.uuid4())
    created_at = datetime.utcnow()
    
    # Validate input
    if not request.url and not request.text and not request.html:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one of url, text, or html must be provided"
        )
    
    # Store scan request in Redis queue
    redis_structs = await get_redis_structures()
    
    scan_data = {
        "scan_id": scan_id,
        "url": request.url,
        "text": request.text,
        "html": request.html,
        "scan_type": request.scan_type,
        "source": request.source,
        "metadata": request.metadata,
        "user_id": request.user_id,
        "created_at": created_at.isoformat()
    }
    
    await redis_structs.add_to_scan_queue(scan_data)
    
    # Update stats
    stats = await get_stats_engine()
    await stats.increment_scan_count(request.scan_type)
    await stats.add_recent_scan({
        "scan_id": scan_id,
        "url": request.url or "text scan",
        "status": "pending"
    })
    
    # Broadcast scan started event
    await ws_manager.broadcast_scan_started(scan_id, request.url or "text scan", request.source)
    
    # Broadcast stats update
    live_stats = await stats.get_live_stats()
    await ws_manager.broadcast_stats_update({
        "scans_today": live_stats.scans_today,
        "threats_blocked": live_stats.threats_blocked
    })
    
    logger.info("Scan created", scan_id=scan_id, type=request.scan_type)
    
    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        estimated_time=5,
        created_at=created_at
    )


@router.get("/scans/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(scan_id: str):
    """Get scan details and results."""
    # Try cache first
    redis_structs = await get_redis_structures()
    cached = await redis_structs.get_cached_scan_result(scan_id)
    
    if cached:
        return ScanDetailResponse(**cached)
    
    # For now, return mock data - in production would query database
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Scan {scan_id} not found"
    )


@router.get("/scans", response_model=RecentScansResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    threat_level: Optional[str] = Query(None),
    scan_type: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None)
):
    """List scans with filtering and pagination."""
    # Get from Redis cache for recent scans
    redis_structs = await get_redis_structures()
    recent = await redis_structs.get_recent_scans(limit)
    
    # In production, this would query the database
    return RecentScansResponse(
        scans=recent,
        total=len(recent)
    )


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan."""
    # In production, would delete from database
    logger.info("Scan deleted", scan_id=scan_id)
    
    return {"success": True, "message": f"Scan {scan_id} deleted"}


# ─── Dashboard Statistics Endpoints ─────────────────────────────────────────

@router.get("/dashboard/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats():
    """Get dashboard statistics - uses mock data for demo, updates with real data when available."""
    from sqlalchemy import select, func
    from app.models.db import Scan as DBScan, RiskLevelEnum
    
    try:
        async for session in get_db_session():
            # Count all scans
            stmt_all = select(func.count(DBScan.id))
            result_all = await session.execute(stmt_all)
            total_scans = result_all.scalar() or 0
            
            # If we have real data, use it
            if total_scans > 0:
                stmt_threats = select(func.count(DBScan.id)).where(DBScan.risk == RiskLevelEnum.HIGH)
                result_threats = await session.execute(stmt_threats)
                threats = result_threats.scalar() or 0
                
                stmt_avg = select(func.avg((DBScan.graph_score + DBScan.model_score) / 2))
                result_avg = await session.execute(stmt_avg)
                avg_score = float(result_avg.scalar() or 0.0)
                
                stmt_low = select(func.count(DBScan.id)).where(DBScan.risk == RiskLevelEnum.LOW)
                stmt_med = select(func.count(DBScan.id)).where(DBScan.risk == RiskLevelEnum.MEDIUM)
                stmt_high = select(func.count(DBScan.id)).where(DBScan.risk == RiskLevelEnum.HIGH)
                
                result_low = await session.execute(stmt_low)
                result_med = await session.execute(stmt_med)
                result_high = await session.execute(stmt_high)
                
                return DashboardStatsResponse(
                    total_scans_today=total_scans,
                    threats_detected_today=threats,
                    avg_risk_score=round(avg_score, 3),
                    scans_per_minute=round(total_scans / 60, 2),
                    active_connections=0,
                    queue_length=0,
                    threat_distribution={
                        "low": result_low.scalar() or 0,
                        "medium": result_med.scalar() or 0,
                        "high": result_high.scalar() or 0
                    }
                )
    except Exception as e:
        logger.warning(f"Dashboard stats query failed: {e}")
    
    # Return mock data for demo - this shows when no real data exists
    return DashboardStatsResponse(
        total_scans_today=127,
        threats_detected_today=23,
        avg_risk_score=0.45,
        scans_per_minute=2.1,
        active_connections=5,
        queue_length=0,
        threat_distribution={"low": 84, "medium": 20, "high": 23}
    )


@router.get("/dashboard/charts/{chart_type}", response_model=ChartDataResponse)
async def get_chart_data(chart_type: str):
    """Get chart data for visualization."""
    
    if chart_type == "threat_trend":
        # Generate mock trend data
        labels = []
        datasets = []
        
        # Last 24 hours
        now = datetime.utcnow()
        for i in range(24):
            hour = (now - timedelta(hours=23-i)).strftime("%H:00")
            labels.append(hour)
        
        return ChartDataResponse(
            labels=labels,
            datasets=[{
                "label": "Threats Detected",
                "data": [10, 15, 8, 12, 20, 18, 25, 22, 15, 10, 8, 12, 15, 18, 22, 20, 15, 12, 10, 8, 15, 18, 20, 22],
                "borderColor": "#ef4444",
                "backgroundColor": "rgba(239, 68, 68, 0.1)"
            }],
            options={"responsive": True, "maintainAspectRatio": False}
        )
    
    elif chart_type == "scan_volume":
        labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        
        return ChartDataResponse(
            labels=labels,
            datasets=[{
                "label": "Scans",
                "data": [120, 150, 180, 160, 200, 90, 80],
                "backgroundColor": "#3b82f6"
            }],
            options={"responsive": True, "maintainAspectRatio": False}
        )
    
    elif chart_type == "top_threats":
        stats = await get_stats_engine()
        live = await stats.get_live_stats()
        
        labels = list(live.threat_distribution.keys())
        data = list(live.threat_distribution.values())
        
        return ChartDataResponse(
            labels=labels,
            datasets=[{
                "label": "Threats",
                "data": data if data else [30, 15, 10, 5, 3],
                "backgroundColor": ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#22c55e"]
            }],
            options={"responsive": True, "maintainAspectRatio": False}
        )
    
    elif chart_type == "risk_distribution":
        return ChartDataResponse(
            labels=["Low", "Medium", "High", "Critical"],
            datasets=[{
                "label": "Risk Distribution",
                "data": [45, 30, 20, 5],
                "backgroundColor": ["#22c55e", "#eab308", "#f97316", "#ef4444"]
            }],
            options={"responsive": True, "maintainAspectRatio": False}
        )
    
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Chart type {chart_type} not found"
        )


@router.get("/dashboard/recent-scans", response_model=RecentScansResponse)
async def get_recent_scans(limit: int = Query(10, ge=1, le=50)):
    """Get recent scans."""
    stats = await get_stats_engine()
    recent = await stats.get_recent_scans(limit)
    
    return RecentScansResponse(
        scans=recent,
        total=len(recent)
    )


@router.get("/dashboard/active-threats", response_model=ActiveThreatsResponse)
async def get_active_threats(limit: int = Query(10, ge=1, le=50)):
    """Get active threats."""
    stats = await get_stats_engine()
    alerts = await stats.get_threat_alerts(limit)
    
    return ActiveThreatsResponse(
        threats=alerts,
        total_count=len(alerts)
    )


# ─── WebSocket Endpoints ───────────────────────────────────────────────────

@router.get("/ws/token", response_model=WebSocketTokenResponse)
async def get_websocket_token():
    """
    Get WebSocket connection token.
    
    In production, this would validate authentication and generate a JWT.
    """
    # Generate a simple token (in production use JWT)
    token = str(uuid.uuid4())
    
    return WebSocketTokenResponse(
        token=token,
        expires_in=3600
    )


@router.websocket("/ws")
async def websocket_connect(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await websocket_endpoint(websocket)


# ─── Alert Configuration Endpoints ─────────────────────────────────────────

@router.post("/alerts/configure")
async def configure_alerts(request: AlertConfigRequest):
    """Configure alert preferences."""
    # Store in Redis
    redis_structs = await get_redis_structures()
    await redis_structs.update_live_stat("alert_config", {
        "alert_types": request.alert_types,
        "notification_channels": request.notification_channels,
        "thresholds": request.thresholds
    })
    
    return {"success": True, "message": "Alert configuration updated"}


@router.get("/alerts/history")
async def get_alert_history(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    alert_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100)
):
    """Get alert history."""
    stats = await get_stats_engine()
    alerts = await stats.get_threat_alerts(limit)
    
    # Filter by type if specified
    if alert_type:
        alerts = [a for a in alerts if a.get("type") == alert_type]
    
    return {"alerts": alerts, "total": len(alerts)}


# ─── Health Check ──────────────────────────────────────────────────────────

@router.get("/realtime/health")
async def realtime_health_check():
    """Health check for real-time services."""
    try:
        redis_client = await get_redis_client()
        await redis_client.ping()
        
        ws_stats = ws_manager.get_stats()
        stats = await get_stats_engine()
        live = await stats.get_live_stats()
        
        return {
            "status": "healthy",
            "websocket": {
                "connected_clients": ws_stats["connected_clients"],
                "messages_sent": ws_stats["messages_sent"]
            },
            "stats": {
                "scans_today": live.scans_today,
                "threats_blocked": live.threats_blocked
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Real-time services unavailable"
        )
