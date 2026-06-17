"""
Pydantic schemas for document anomaly heatmap system.
"""
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class HeatmapRegion(BaseModel):
    """A single suspicious region detected in the document."""
    x: int = Field(..., description="Top-left X coordinate")
    y: int = Field(..., description="Top-left Y coordinate")
    width: int = Field(..., description="Region width in pixels")
    height: int = Field(..., description="Region height in pixels")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score for this region")
    reason: str = Field(..., description="Why this region is flagged")
    region_type: str = Field(default="suspicious", description="Type: text, form, url, logo, hidden")


class DocumentHeatmapRequest(BaseModel):
    """Request to generate a document anomaly heatmap."""
    scan_id: Optional[str] = Field(None, description="Existing scan ID to correlate with")
    file_path: str = Field(..., description="Path to the document image or PDF page")
    page_number: int = Field(default=1, ge=1, description="Page number (for multi-page docs)")
    threshold: float = Field(default=0.5, ge=0.0, le=1.0, description="Sensitivity threshold")


class DocumentHeatmapResponse(BaseModel):
    """Response containing heatmap analysis results."""
    status: str = "completed"
    scan_id: Optional[str] = None
    page_number: int = 1
    total_pages: int = 1
    image_width: int = 0
    image_height: int = 0
    regions: List[HeatmapRegion] = []
    overlay_image: Optional[str] = Field(None, description="Base64-encoded PNG overlay image")
    analysis_time_ms: int = 0
    warnings: List[str] = []
