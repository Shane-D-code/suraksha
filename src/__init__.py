"""
PhishGuard Modular Detection Architecture

This package provides a modular architecture for phishing detection:
- ONNX Pipeline: Optimized NLP inference
- Visual Pipeline: CNN-based screenshot analysis
- SHAP Pipeline: Explainable AI explanations
- Fusion Engine: Central brain combining all components
"""

__version__ = "1.0.0"

from src.fusion_engine import PhishingFusionEngine
from src.onnx_pipeline import ONNXPipeline
from src.visual_pipeline import VisualInspector
from src.shap_pipeline import ExplainerEngine

__all__ = [
    "PhishingFusionEngine",
    "ONNXPipeline", 
    "VisualInspector",
    "ExplainerEngine",
]
