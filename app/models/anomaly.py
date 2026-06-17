"""
Pydantic schemas for the Novel Anomaly Detection module.

Detects unknown fraud patterns, layout anomalies, outlier financial
values, and unusual metadata combinations using three approaches:
- Isolation Forest (multivariate outlier detection)
- Autoencoder (reconstruction-based deep anomaly detection)
- Statistical outlier methods (Z-score / IQR)

Each approach produces an anomaly_score 0.0–1.0 (higher = more anomalous)
and a confidence 0.0–1.0. The engine fuses them into a single finding.
"""
from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum


class AnomalyMethod(str, Enum):
    ISOLATION_FOREST = "isolation_forest"
    AUTOENCODER = "autoencoder"
    STATISTICAL = "statistical"
    FUSION = "fusion"


class FieldFeature(BaseModel):
    name: str = Field(..., description="Feature / field name (e.g. 'document_version', 'total_amount')")
    value: float = Field(..., description="Numerical value of the feature")
    category: str = Field(default="general", description="Feature category: metadata, layout, financial, unknown")


class AnomalyDetectionRequest(BaseModel):
    fields: List[FieldFeature] = Field(..., description="List of named numerical features to analyse")
    reference_sample: Optional[List[List[float]]] = Field(
        None, description="Optional historical baseline matrix (rows=samples, cols=fields) for Isolation Forest fit"
    )
    context: Optional[str] = Field(None, description="Document context hint (e.g. 'invoice', 'tax form')")


class AnomalyResult(BaseModel):
    method: AnomalyMethod = Field(..., description="Which method detected this anomaly")
    anomaly_score: float = Field(..., ge=0.0, le=1.0, description="0.0 = normal, 1.0 = maximally anomalous")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in this detection")
    top_features: List[str] = Field(default_factory=list, description="Features that most contributed to the anomaly")
    explanation: str = Field(..., description="Human-readable explanation of what was detected")
    severity: str = Field(default="MEDIUM", description="LOW / MEDIUM / HIGH / CRITICAL")
    details: dict = Field(default_factory=dict, description="Additional method-specific diagnostic info")


class AnomalyDetectionResponse(BaseModel):
    findings: List[AnomalyResult] = Field(..., description="Individual anomaly findings, one per method")
    fusion_score: float = Field(..., ge=0.0, le=1.0, description="Weighted fusion of all method scores")
    fusion_severity: str = Field(default="MEDIUM", description="Aggregate severity across methods")
    summary: str = Field(..., description="Plain-English summary of the overall assessment")
    method_count: int = Field(..., description="Number of methods that contributed to the result")
    analysis_time_ms: int = Field(default=0, description="Processing time in milliseconds")
