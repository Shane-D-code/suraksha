"""
Rate limiting middleware using Redis.
"""
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import structlog
import time

from app.config import settings

logger = structlog.get_logger(__name__)


def get_remote_address(request: Request) -> str:
    """Get remote address from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0]
    return request.client.host if request.client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using Redis."""
    
    def __init__(self, app):
        super().__init__(app)
        self.rate_limit = settings.RATE_LIMIT_PER_MINUTE
        self.window = 60  # 1 minute window
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Process request with rate limiting."""
        # Skip rate limiting for health checks
        skip_paths = ["/health", "/", "/docs", "/redoc", "/openapi.json"]
        if request.url.path in skip_paths:
            return await call_next(request)
        
        # Get the rate limit key
        key = get_rate_limit_key(request)
        
        # Check rate limit using Redis
        try:
            from app.services.redis import get_redis_client
            redis = await get_redis_client()
            
            # Create rate limit key
            rate_key = f"rate_limit:{key}:{int(time.time() // self.window)}"
            
            # Increment counter
            current = await redis.incr(rate_key)
            
            # Set expiry on first request
            if current == 1:
                await redis.expire(rate_key, self.window)
            
            # Check if limit exceeded
            if current > self.rate_limit:
                logger.warning("Rate limit exceeded", ip=key, count=current)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded. Please try again later.",
                    headers={"Retry-After": str(self.window)},
                )
        except HTTPException:
            raise
        except Exception as e:
            # If rate limiting fails, allow request but log error
            logger.error("Rate limiting error", error=str(e))
        
        response = await call_next(request)
        return response


def get_rate_limit_key(request: Request) -> str:
    """Get rate limit key based on IP or user."""
    # Check for authenticated user
    if hasattr(request.state, "user"):
        return f"user:{request.state.user}"
    return f"ip:{get_remote_address(request)}"
