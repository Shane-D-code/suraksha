"""
Pydantic schemas for the Explainable AI (XAI) module.

Maps raw findings from five analysis pipelines into plain-English
explanations with confidence levels, risk impact, and recommendations.
"""
from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum


class FindingCategory(str, Enum):
    METADATA = "metadata"
    ELA = "ela"
    OCR = "ocr"
    NUMERIC = "numeric"
    SIGNATURE = "signature"


class XaiInputFinding(BaseModel):
    category: FindingCategory = Field(..., description="Source analysis category")
    finding_type: str = Field(..., description="Specific finding type within the category")
    description: str = Field(..., description="Raw finding description or detected value")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence in this finding")
    details: dict = Field(default_factory=dict, description="Additional structured details")


class XaiRequest(BaseModel):
    findings: List[XaiInputFinding] = Field(..., description="Findings from all analysis pipelines")
    document_context: Optional[str] = Field(None, description="Optional document type context (e.g. invoice, ID proof, bank statement)")


class XaiExplanation(BaseModel):
    model_config = {"protected_namespaces": ()}

    finding_type: str = Field(..., description="Which finding this explains")
    plain_english: str = Field(..., description="Human-readable explanation in plain English")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in this explanation")
    risk_impact: str = Field(..., description="What risk this finding poses")
    recommendation: str = Field(..., description="What action to take")
    severity: str = Field(default="MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")


class XaiResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    explanations: List[XaiExplanation] = Field(..., description="Generated explanations")
    summary: str = Field(..., description="Overall assessment summary")
    overall_confidence: float = Field(..., ge=0.0, le=1.0, description="Aggregated confidence")
    overall_severity: str = Field(default="MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    top_recommendation: str = Field(default="", description="Most critical action to take")
