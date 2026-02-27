"""
API routes package.
"""
from app.api.routes import router
from app.api.forensic_routes import router as forensic_router

__all__ = ["router", "forensic_router"]
