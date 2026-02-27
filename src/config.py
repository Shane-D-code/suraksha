"""
Configuration for PhishGuard Modular Architecture

This module contains configuration settings for:
- ONNX Pipeline
- Visual Pipeline  
- SHAP Pipeline
- Fusion Engine
"""

import os
from pathlib import Path
from typing import Dict, Any, List, Optional


# Get project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODELS_DIR = PROJECT_ROOT / "models"
DATA_DIR = PROJECT_ROOT / "data"


class ONNXConfig:
    """Configuration for ONNX Pipeline."""
    
    # Model settings
    MODEL_NAME = "phish_model.joblib"
    VECTORIZER_NAME = "tfidf_vectorizer.joblib"
    MODEL_DIR = str(MODELS_DIR)
    
    # Quantization settings
    USE_QUANTIZATION = True
    QUANT_TYPE = "QInt8"  # QInt8 or QUInt8
    
    # Inference settings
    PROVIDERS = ["CPUExecutionProvider"]  # Add "CUDAExecutionProvider" for GPU
    GRAPH_OPTIMIZATION = True
    INTRA_OP_THREADS = 4
    INTER_OP_THREADS = 4
    
    # ONNX export settings
    OPSET_VERSION = 13
    DYNAMIC_AXES = {
        'input_ids': {0: 'batch_size', 1: 'sequence_length'},
        'attention_mask': {0: 'batch_size', 1: 'sequence_length'},
        'output': {0: 'batch_size'}
    }


class VisualConfig:
    """Configuration for Visual Pipeline."""
    
    # Model settings
    MODEL_TYPE = "resnet18"  # resnet18, resnet50, efficientnet_b0
    PRETRAINED = True
    DEVICE = "cpu"  # cpu or cuda
    
    # Image preprocessing
    IMAGE_SIZE = (224, 224)
    NORMALIZE_MEAN = [0.485, 0.456, 0.406]
    NORMALIZE_STD = [0.229, 0.224, 0.225]
    
    # Brand template settings
    TEMPLATE_DIR = str(MODELS_DIR / "templates")
    
    # Detection thresholds
    SIMILARITY_THRESHOLD = 0.85
    IMPERSONATION_THRESHOLD = 0.85
    
    # Supported image formats
    SUPPORTED_FORMATS = [".jpg", ".jpeg", ".png", ".webp", ".bmp"]


class SHAPConfig:
    """Configuration for SHAP Pipeline."""
    
    # Algorithm settings
    ALGORITHM = "auto"  # auto, tree, linear, deep, kernel
    
    # Background data settings
    BACKGROUND_SAMPLES = 100
    MAX背景 = 1000
    
    # Explanation settings
    TOP_N_FEATURES = 10
    MIN_IMPACT_THRESHOLD = 0.01
    
    # Feature name mappings
    FEATURE_NAMES = [
        # URL features
        'url_length', 'num_dots', 'num_hyphens', 'num_underscores',
        'num_slashes', 'num_subdomains', 'has_ip', 'suspicious_tld',
        'url_entropy', 'num_special_chars',
        
        # Content features
        'urgency_score', 'brand_detected', 'login_form', 'password_field',
        'external_resources', 'hidden_elements', 'iframe_count',
        'script_count', 'obfuscated_text',
        
        # Domain features
        'domain_age', 'ssl_valid', 'gnn_similarity', ' registrar',
        'registrant_country', 'asn_reputation',
        
        # NLP features (TF-IDF keywords)
    ] + [f'tfidf_{i}' for i in range(80)]
    
    # Reason mappings
    REASON_MAPPINGS = {
        'url_length': lambda v: "Abnormally long URL" if v > 80 else "Long URL",
        'num_subdomains': lambda v: "Excessive subdomains" if v > 3 else None,
        'has_ip': lambda v: "IP address in URL" if v == 1 else None,
        'urgency_score': lambda v: "High urgency language" if v > 0.7 else "Urgency language detected",
        'suspicious_tld': lambda v: "Suspicious TLD" if v == 1 else None,
        'brand_detected': lambda v: "Brand impersonation" if v == 1 else None,
        'login_form': lambda v: "Login form detected" if v == 1 else None,
        'password_field': lambda v: "Password field - credential harvesting risk" if v == 1 else None,
        'external_resources': lambda v: "External resources - data exfiltration risk" if v > 3 else None,
        'hidden_elements': lambda v: "Hidden elements - deception attempt" if v > 0 else None,
    }


class FusionConfig:
    """Configuration for Fusion Engine."""
    
    # Pipeline weights
    NLP_WEIGHT = 0.6
    VISUAL_WEIGHT = 0.4
    
    # Thresholds
    NLP_THRESHOLD = 0.5
    VISUAL_THRESHOLD = 0.85
    FUSION_THRESHOLD = 0.5
    
    # Feature toggles
    ENABLE_SHAP = True
    ENABLE_VISUAL = True
    ENABLE_NLP = True
    
    # Processing settings
    MAX_REASONS = 5
    MAX_FINDINGS = 10
    BATCH_SIZE = 32
    
    # Risk level thresholds
    RISK_THRESHOLDS = {
        'LOW': 0.2,
        'MEDIUM': 0.4,
        'HIGH': 0.6,
        'CRITICAL': 0.8
    }


# Model version tracking
MODEL_VERSIONS = {
    'nlp': {
        'model': ONNXConfig.MODEL_NAME,
        'vectorizer': ONNXConfig.VECTORIZER_NAME,
        'format': 'onnx'
    },
    'visual': {
        'model': VisualConfig.MODEL_TYPE,
        'pretrained': VisualConfig.PRETRAINED
    },
    'shap': {
        'algorithm': SHAPConfig.ALGORITHM
    }
}


def get_config(pipeline: str = None) -> Dict[str, Any]:
    """
    Get configuration for a specific pipeline.
    
    Args:
        pipeline: Pipeline name ('onnx', 'visual', 'shap', 'fusion')
        
    Returns:
        Configuration dictionary
    """
    configs = {
        'onnx': ONNXConfig.__dict__,
        'visual': VisualConfig.__dict__,
        'shap': SHAPConfig.__dict__,
        'fusion': FusionConfig.__dict__
    }
    
    if pipeline:
        return configs.get(pipeline.lower(), {})
    
    return {
        'onnx': dict(ONNXConfig.__dict__),
        'visual': dict(VisualConfig.__dict__),
        'shap': dict(SHAPConfig.__dict__),
        'fusion': dict(FusionConfig.__dict__)
    }


def get_model_paths() -> Dict[str, str]:
    """Get paths to all model files."""
    return {
        'nlp_model': str(MODELS_DIR / ONNXConfig.MODEL_NAME),
        'vectorizer': str(MODELS_DIR / ONNXConfig.VECTORIZER_NAME),
        'templates': VisualConfig.TEMPLATE_DIR,
        'models_dir': str(MODELS_DIR)
    }


# Export configuration
__all__ = [
    'ONNXConfig',
    'VisualConfig', 
    'SHAPConfig',
    'FusionConfig',
    'MODEL_VERSIONS',
    'get_config',
    'get_model_paths',
    'PROJECT_ROOT',
    'MODELS_DIR',
    'DATA_DIR'
]
