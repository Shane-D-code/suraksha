"""
Main FastAPI application entry point.
"""
import asyncio
import logging
import uuid
import hashlib
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import structlog

from app.config import settings
from app.api.routes import router as api_router
from app.api.forensic_routes import router as forensic_router
from app.api.realtime_routes import router as realtime_router
from app.middleware.rate_limit import RateLimitMiddleware
from app.services.database import init_db, close_db
from app.services.redis import init_redis, close_redis, get_redis_client
from app.services.threat_graph_engine import ThreatGraphEngine, init_threat_engine
from app.services.websocket_manager import ws_manager
from app.services.realtime_stats_engine import get_stats_engine

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Global instances
threat_engine = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup and shutdown events."""
    global threat_engine
    
    # Startup
    logger.info("Starting application", 
                app_name=settings.APP_NAME, 
                version=settings.APP_VERSION,
                environment=settings.ENVIRONMENT)
    logger.info(f"Redis URL: {settings.REDIS_URL}")
    logger.info(f"Database: {settings.DATABASE_URL.split('@')[-1] if '@' in settings.DATABASE_URL else 'local'}")
    
    # Initialize database
    await init_db()
    logger.info("Database initialized")
    
    # Initialize Redis
    await init_redis()
    logger.info("Redis initialized")
    
    # Initialize WebSocket Manager
    try:
        await ws_manager.start()
        logger.info("WebSocket Manager started")
    except Exception as e:
        logger.warning(f"WebSocket Manager initialization failed: {e}")
    
    # Initialize Real-Time Stats Engine
    try:
        await get_stats_engine()
        logger.info("Real-Time Stats Engine started")
    except Exception as e:
        logger.warning(f"Real-Time Stats Engine initialization failed: {e}")
    
    # Initialize threat feeds (if enabled)
    try:
        from app.services.threat_feeds import get_feed_aggregator
        feed_aggregator = get_feed_aggregator()
        feed_status = feed_aggregator.get_status()
        enabled_feeds = [f["name"] for f in feed_status if f["enabled"]]
        if enabled_feeds:
            logger.info(f"Threat feeds enabled: {enabled_feeds}")
            # Initial fetch in background
            asyncio.create_task(fetch_initial_feeds())
        else:
            logger.info("No threat feeds enabled (set OPENPHISH_ENABLED=true etc.)")
    except Exception as e:
        logger.warning(f"Threat feeds initialization failed: {e}")
    
    # Initialize Person 3 ThreatGraphEngine
    try:
        redis_client = await get_redis_client()
        from app.services import database as db_service
        # Use helper to initialize global instance
        await init_threat_engine(db_pool=db_service.db_pool, redis_client=redis_client)
        logger.info("Person 3 ThreatGraphEngine initialized")
    except Exception as e:
        logger.warning(f"ThreatGraphEngine initialization failed: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application")
    if threat_engine:
        await threat_engine.shutdown()
    
    # Stop WebSocket Manager
    try:
        await ws_manager.stop()
        logger.info("WebSocket Manager stopped")
    except Exception as e:
        logger.warning(f"WebSocket Manager shutdown failed: {e}")
    
    await close_redis()
    await close_db()
    logger.info("Application shutdown complete")


async def fetch_initial_feeds():
    """Fetch initial threat feeds in background after startup."""
    try:
        from app.services.threat_feeds import get_feed_aggregator
        await asyncio.sleep(5)  # Wait for app to fully start
        aggregator = get_feed_aggregator()
        indicators = await aggregator.fetch_all()
        logger.info(f"Initial threat feeds fetched: {len(indicators)} indicators")
    except Exception as e:
        logger.warning(f"Initial feed fetch failed: {e}")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Endpoint Threat Intelligence Platform Core API",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add rate limiting middleware
app.add_middleware(RateLimitMiddleware)


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle uncaught exceptions globally."""
    logger.error(
        "Uncaught exception",
        path=request.url.path,
        method=request.method,
        error=str(exc),
        error_type=type(exc).__name__,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# Include API routes
app.include_router(api_router, prefix=settings.API_PREFIX)
app.include_router(forensic_router, prefix=settings.API_PREFIX)
app.include_router(realtime_router, prefix=settings.API_PREFIX)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        workers=1 if settings.DEBUG else settings.WORKERS,
    )
