"""
Pydantic schemas for signature verification system.
"""
from pydantic import BaseModel, Field
from typing import Optional


class SignatureVerifyRequest(BaseModel):
    """Request to verify a signature against a reference."""
    reference_path: str = Field(..., description="Path to the reference (genuine) signature image")
    submitted_path: str = Field(..., description="Path to the submitted signature image to verify")
    document_id: Optional[str] = Field(None, description="Associated document ID for risk integration")
    scan_id: Optional[str] = Field(None, description="Existing scan ID to correlate with")


class SignatureVerifyResponse(BaseModel):
    model_config = {"protected_namespaces": ()}
    """Response containing signature verification results."""
    status: str = "completed"
    similarity_score: float = Field(..., ge=0.0, le=1.0, description="Cosine similarity between signature embeddings")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the verification result")
    is_forgery: bool = Field(..., description="Classification: True if likely forged")
    threshold_used: float = Field(..., description="Decision threshold applied")
    analysis_time_ms: int = 0
    embedding_dim: int = Field(default=0, description="Dimension of the feature embedding")
    model_used: str = Field(default="", description="Model name used for verification")
    error: Optional[str] = None
