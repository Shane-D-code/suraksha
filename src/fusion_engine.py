"""
Fusion Engine - Central Brain for Phishing Detection

This module combines:
1. ONNX Pipeline: NLP-based text/URL analysis
2. Visual Pipeline: CNN-based screenshot analysis  
3. SHAP Pipeline: Explainable AI explanations

The Fusion Engine provides a unified interface for comprehensive phishing detection.
"""

import os
import logging
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

logger = logging.getLogger(__name__)

# Import pipeline components
from src.onnx_pipeline import ONNXPipeline, create_onnx_pipeline
from src.visual_pipeline import VisualInspector, create_visual_inspector, BrandTemplateManager
from src.shap_pipeline import ExplainerEngine, create_explainer


class RiskLevel(str, Enum):
    """Risk classification levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AnalysisResult:
    """
    Unified analysis result from all pipelines.
    
    Contains:
    - Combined risk score
    - Risk level classification
    - Individual pipeline results
    - SHAP explanations
    - Visual analysis results (if screenshot provided)
    """
    # Overall assessment
    risk_score: float
    risk_level: RiskLevel
    confidence: float
    is_phishing: bool
    
    # NLP/ONNX results
    nlp_result: Dict[str, Any] = field(default_factory=dict)
    
    # Visual results
    visual_result: Dict[str, Any] = field(default_factory=dict)
    
    # SHAP explanations
    explanations: List[Dict[str, Any]] = field(default_factory=list)
    
    # Raw findings
    findings: List[str] = field(default_factory=list)
    
    # Metadata
    model_versions: Dict[str, str] = field(default_factory=dict)
    processing_time_ms: float = 0.0
    
    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        return {
            'risk_score': self.risk_score,
            'risk_level': self.risk_level.value,
            'confidence': self.confidence,
            'is_phishing': self.is_phishing,
            'nlp_analysis': self.nlp_result,
            'visual_analysis': self.visual_result,
            'explanations': self.explanations,
            'findings': self.findings,
            'model_versions': self.model_versions,
            'processing_time_ms': self.processing_time_ms
        }


class PhishingFusionEngine:
    """
    Central fusion engine that combines all detection pipelines.
    
    Features:
    - Unified analysis interface
    - Parallel pipeline execution where possible
    - Weighted scoring based on pipeline confidence
    - SHAP explanations for all predictions
    - Visual analysis integration
    """
    
    def __init__(
        self,
        nlp_pipeline: Optional[ONNXPipeline] = None,
        visual_inspector: Optional[VisualInspector] = None,
        shap_explainer: Optional[ExplainerEngine] = None,
        model_dir: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the Fusion Engine.
        
        Args:
            nlp_pipeline: ONNX pipeline for NLP analysis
            visual_inspector: Visual inspector for screenshots
            shap_explainer: SHAP explainer
            model_dir: Directory containing models
            config: Configuration options
        """
        self.config = config or self._default_config()
        self.model_dir = model_dir or self._get_default_model_dir()
        
        # Initialize pipelines
        self.nlp_pipeline = nlp_pipeline or self._init_nlp_pipeline()
        self.visual_inspector = visual_inspector or self._init_visual_inspector()
        self.shap_explainer = shap_explainer or self._init_shap_explainer()
        
        # Brand template manager
        self.brand_manager = BrandTemplateManager(
            os.path.join(self.model_dir, 'templates')
        )
        
        # Pipeline weights for fusion
        self.weights = {
            'nlp': self.config.get('nlp_weight', 0.6),
            'visual': self.config.get('visual_weight', 0.4)
        }
        
        logger.info("PhishingFusionEngine initialized")
        logger.info(f"  NLP Pipeline: {type(self.nlp_pipeline).__name__}")
        logger.info(f"  Visual Inspector: {type(self.visual_inspector).__name__}")
        logger.info(f"  SHAP Explainer: {type(self.shap_explainer).__name__}")
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration."""
        return {
            'nlp_weight': 0.6,
            'visual_weight': 0.4,
            'nlp_threshold': 0.5,
            'visual_threshold': 0.85,
            'fusion_threshold': 0.5,
            'enable_shap': True,
            'enable_visual': True,
            'max_reasons': 5
        }
    
    def _get_default_model_dir(self) -> str:
        """Get default model directory."""
        # Try multiple paths
        possible_paths = [
            os.path.join(os.path.dirname(__file__), '..', 'models'),
            os.path.join(os.path.dirname(__file__), '..', '..', 'models'),
            os.path.join(os.getcwd(), 'models')
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        return possible_paths[0]
    
    def _init_nlp_pipeline(self) -> ONNXPipeline:
        """Initialize NLP pipeline."""
        try:
            return create_onnx_pipeline(
                model_dir=self.model_dir,
                model_name='phish_model.joblib',
                use_quantization=True
            )
        except Exception as e:
            logger.warning(f"Failed to initialize NLP pipeline: {e}")
            return ONNXPipeline(model_path=os.path.join(self.model_dir, 'phish_model.joblib'))
    
    def _init_visual_inspector(self) -> VisualInspector:
        """Initialize visual inspector."""
        try:
            return create_visual_inspector(
                model_path=None,
                brand_template_path=None,
                device='cpu'
            )
        except Exception as e:
            logger.warning(f"Failed to initialize visual inspector: {e}")
            return VisualInspector()
    
    def _init_shap_explainer(self) -> ExplainerEngine:
        """Initialize SHAP explainer."""
        try:
            model_path = os.path.join(self.model_dir, 'phish_model.joblib')
            return create_explainer(
                model_path=model_path if os.path.exists(model_path) else None
            )
        except Exception as e:
            logger.warning(f"Failed to initialize SHAP explainer: {e}")
            return create_explainer()
    
    def analyze(
        self,
        text: Optional[str] = None,
        url: Optional[str] = None,
        html: Optional[str] = None,
        screenshot_path: Optional[str] = None,
        features: Optional[Dict[str, Any]] = None,
        return_details: bool = True
    ) -> AnalysisResult:
        """
        Main analysis entry point.
        
        Combines NLP, visual, and SHAP analysis for comprehensive detection.
        
        Args:
            text: Text content to analyze (email body, etc.)
            url: URL to analyze
            html: HTML content to analyze
            screenshot_path: Path to screenshot image
            features: Pre-extracted features dict
            return_details: Whether to return detailed explanations
            
        Returns:
            AnalysisResult with unified assessment
        """
        import time
        start_time = time.time()
        
        results = {
            'nlp': {},
            'visual': {},
            'explanations': [],
            'findings': []
        }
        
        # 1. NLP Analysis
        nlp_result = self._analyze_nlp(text, url, html, features)
        results['nlp'] = nlp_result
        
        # 2. Visual Analysis (if screenshot provided)
        if screenshot_path and self.config.get('enable_visual', True):
            visual_result = self._analyze_visual(screenshot_path, url)
            results['visual'] = visual_result
        
        # 3. Generate explanations
        if self.config.get('enable_shap', True) and features:
            explanations = self._generate_explanations(features, nlp_result)
            results['explanations'] = explanations
        
        # 4. Collect findings
        results['findings'] = self._collect_findings(nlp_result, results['visual'])
        
        # 5. Fuse results
        fused_result = self._fuse_results(
            nlp_result,
            results['visual'],
            results['explanations'],
            results['findings']
        )
        
        # Calculate processing time
        processing_time = (time.time() - start_time) * 1000
        
        # Build final result
        return AnalysisResult(
            risk_score=fused_result['risk_score'],
            risk_level=fused_result['risk_level'],
            confidence=fused_result['confidence'],
            is_phishing=fused_result['is_phishing'],
            nlp_result=results['nlp'],
            visual_result=results['visual'],
            explanations=results['explanations'],
            findings=results['findings'],
            model_versions=self._get_model_versions(),
            processing_time_ms=round(processing_time, 2)
        )
    
    def _analyze_nlp(
        self,
        text: Optional[str],
        url: Optional[str],
        html: Optional[str],
        features: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Run NLP analysis."""
        result = {
            'method': 'unknown',
            'score': 0.5,
            'is_phishing': False,
            'confidence': 0.5
        }
        
        try:
            # Use features if provided
            if features:
                # Extract features as numpy array
                feature_array = self._features_to_array(features)
                prediction = self.nlp_pipeline.predict(feature_array)
                
                result = {
                    'method': 'ml',
                    'score': float(prediction.get('confidence', 0.5)),
                    'is_phishing': bool(prediction.get('prediction', 0)),
                    'confidence': float(prediction.get('confidence', 0.5)),
                    'probabilities': prediction.get('probabilities', [0.5, 0.5])
                }
            
            # Otherwise use text/URL analysis
            elif text or url:
                if text:
                    feature_array = self.nlp_pipeline.extract_features(text)
                    prediction = self.nlp_pipeline.predict(feature_array)
                    
                    result = {
                        'method': 'ml',
                        'score': float(prediction.get('confidence', 0.5)),
                        'is_phishing': bool(prediction.get('prediction', 0)),
                        'confidence': float(prediction.get('confidence', 0.5)),
                        'text_analyzed': True
                    }
                elif url:
                    # Simple URL analysis
                    result = self._analyze_url(url)
        
        except Exception as e:
            logger.error(f"NLP analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    def _analyze_url(self, url: str) -> Dict[str, Any]:
        """Simple URL-based analysis."""
        score = 0.0
        findings = []
        
        # Check for suspicious patterns
        import re
        
        # IP address in URL
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            score += 0.3
            findings.append("URL contains IP address")
        
        # Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work']
        if any(url.lower().endswith(tld) for tld in suspicious_tlds):
            score += 0.25
            findings.append("Suspicious free TLD")
        
        # Excessive subdomains
        if url.count('.') > 3:
            score += 0.15
            findings.append("Excessive subdomains")
        
        # Brand keywords in URL
        brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix']
        for brand in brands:
            if brand in url.lower():
                score += 0.2
                findings.append(f"Brand keyword in URL: {brand}")
                break
        
        # Phishing keywords
        phishing_keywords = ['verify', 'secure', 'account', 'update', 'confirm', 'login']
        for kw in phishing_keywords:
            if kw in url.lower():
                score += 0.1
                findings.append(f"Phishing keyword: {kw}")
        
        return {
            'method': 'rule_based',
            'score': min(score, 1.0),
            'is_phishing': score >= 0.5,
            'confidence': min(score + 0.3, 1.0),
            'findings': findings,
            'url_analyzed': True
        }
    
    def _analyze_visual(
        self,
        screenshot_path: str,
        url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run visual analysis."""
        result = {
            'screenshot_analyzed': False,
            'visual_match_score': 0.0,
            'is_impersonation': False,
            'confidence': 0.0
        }
        
        try:
            if not os.path.exists(screenshot_path):
                logger.warning(f"Screenshot not found: {screenshot_path}")
                result['error'] = "Screenshot file not found"
                return result
            
            # Try brand template if available
            if self.visual_inspector.brand_template is not None:
                detection = self.visual_inspector.detect_impersonation(screenshot_path)
                result = {
                    'screenshot_analyzed': True,
                    'visual_match_score': detection['visual_match_score'],
                    'is_impersonation': detection['is_impersonation'],
                    'confidence': detection['confidence'],
                    'brand': detection.get('brand'),
                    'interpretation': detection.get('interpretation')
                }
            else:
                result['message'] = "No brand template loaded"
        
        except Exception as e:
            logger.error(f"Visual analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    def _generate_explanations(
        self,
        features: Dict[str, Any],
        nlp_result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate SHAP explanations."""
        try:
            explanation = self.shap_explainer.explain_prediction(
                features,
                feature_values=features,
                top_n=self.config.get('max_reasons', 5)
            )
            
            return explanation.get('reasons', [])
        
        except Exception as e:
            logger.error(f"Explanation generation failed: {e}")
            return []
    
    def _collect_findings(
        self,
        nlp_result: Dict[str, Any],
        visual_result: Dict[str, Any]
    ) -> List[str]:
        """Collect all findings from pipelines."""
        findings = []
        
        # NLP findings
        if nlp_result.get('findings'):
            findings.extend(nlp_result['findings'])
        
        if nlp_result.get('is_phishing'):
            findings.append(f"NLP model detected phishing (confidence: {nlp_result.get('confidence', 0):.2f})")
        
        # Visual findings
        if visual_result.get('is_impersonation'):
            findings.append(f"Visual impersonation detected (score: {visual_result.get('visual_match_score', 0):.2f})")
        
        return findings[:10]  # Limit to top 10
    
    def _fuse_results(
        self,
        nlp_result: Dict[str, Any],
        visual_result: Dict[str, Any],
        explanations: List[Dict],
        findings: List[str]
    ) -> Dict[str, Any]:
        """Fuse results from all pipelines."""
        
        # Start with NLP score
        nlp_score = nlp_result.get('score', 0.5)
        nlp_confidence = nlp_result.get('confidence', 0.5)
        
        # Incorporate visual score if available
        visual_score = visual_result.get('visual_match_score', 0.5)
        
        # Visual impersonation detection:
        # Low visual match = potential impersonation
        # But we need to factor this into phishing score
        visual_phishing_indicator = 0.0
        if visual_result.get('screenshot_analyzed'):
            if visual_result.get('is_impersonation'):
                visual_phishing_indicator = 0.7  # Strong indicator
            else:
                visual_phishing_indicator = 1.0 - visual_score  # Higher score = more legitimate
        
        # Calculate weighted fusion
        if visual_result.get('screenshot_analyzed'):
            # Weighted combination
            final_score = (
                self.weights['nlp'] * nlp_score +
                self.weights['visual'] * visual_phishing_indicator
            )
            final_confidence = (
                self.weights['nlp'] * nlp_confidence +
                self.weights['visual'] * visual_result.get('confidence', 0.5)
            )
        else:
            final_score = nlp_score
            final_confidence = nlp_confidence
        
        # Determine risk level
        if final_score >= 0.8:
            risk_level = RiskLevel.CRITICAL
        elif final_score >= 0.6:
            risk_level = RiskLevel.HIGH
        elif final_score >= 0.4:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        return {
            'risk_score': round(final_score, 3),
            'risk_level': risk_level,
            'confidence': round(final_confidence, 3),
            'is_phishing': final_score >= self.config.get('fusion_threshold', 0.5)
        }
    
    def _features_to_array(self, features: Dict[str, Any]) -> np.ndarray:
        """Convert feature dict to numpy array."""
        # Use SHAP explainer's feature names
        feature_names = self.shap_explainer.feature_names
        
        # Create array with default values
        arr = np.zeros(len(feature_names), dtype=np.float32)
        
        for i, name in enumerate(feature_names):
            if name in features:
                arr[i] = float(features[name])
            else:
                # Try to find partial matches
                for key in features:
                    if key.lower() in name.lower() or name.lower() in key.lower():
                        arr[i] = float(features[key])
                        break
        
        return arr
    
    def _get_model_versions(self) -> Dict[str, str]:
        """Get versions of all models."""
        versions = {}
        
        # NLP pipeline
        if self.nlp_pipeline:
            versions['nlp'] = self.nlp_pipeline._model_type or 'unknown'
        
        # Visual inspector
        if self.visual_inspector and self.visual_inspector.model:
            versions['visual'] = type(self.visual_inspector.model).__name__
        
        # SHAP explainer
        if self.shap_explainer:
            versions['shap'] = self.shap_explainer._model_type
        
        return versions
    
    def set_brand_template(self, template_path: str, brand_name: str = None) -> bool:
        """Set brand template for visual analysis."""
        return self.visual_inspector.load_brand_template(template_path, brand_name)
    
    def analyze_batch(
        self,
        items: List[Dict[str, Any]]
    ) -> List[AnalysisResult]:
        """Analyze multiple items."""
        results = []
        
        for item in items:
            result = self.analyze(
                text=item.get('text'),
                url=item.get('url'),
                html=item.get('html'),
                screenshot_path=item.get('screenshot_path'),
                features=item.get('features')
            )
            results.append(result)
        
        return results


# Factory function
def create_fusion_engine(
    model_dir: str = None,
    config: Dict[str, Any] = None
) -> PhishingFusionEngine:
    """
    Create a PhishingFusionEngine instance.
    
    Args:
        model_dir: Directory containing models
        config: Configuration options
        
    Returns:
        PhishingFusionEngine instance
    """
    return PhishingFusionEngine(
        model_dir=model_dir,
        config=config
    )


# Convenience function for simple analysis
def quick_analyze(
    text: str = None,
    url: str = None,
    model_dir: str = None
) -> Dict[str, Any]:
    """
    Quick analysis function for simple use cases.
    
    Args:
        text: Text to analyze
        url: URL to analyze
        model_dir: Model directory path
        
    Returns:
        Analysis result dictionary
    """
    engine = create_fusion_engine(model_dir=model_dir)
    result = engine.analyze(text=text, url=url)
    return result.to_dict()


if __name__ == "__main__":
    # Test the fusion engine
    print("Testing PhishingFusionEngine...")
    
    engine = create_fusion_engine()
    
    # Test cases
    test_cases = [
        {
            'text': "Your account has been suspended. Verify now to avoid closure!",
            'url': "https://paypal-verify-account.xyz/login"
        },
        {
            'text': "Welcome to our website, how can I help you?",
            'url': "https://www.example.com"
        },
        {
            'url': "https://192.168.1.1/login.php"  # IP-based URL
        }
    ]
    
    for i, test in enumerate(test_cases):
        print(f"\n{'='*50}")
        print(f"Test Case {i+1}")
        print(f"{'='*50}")
        
        result = engine.analyze(
            text=test.get('text'),
            url=test.get('url')
        )
        
        print(f"\nResult:")
        print(f"  Risk Score: {result.risk_score}")
        print(f"  Risk Level: {result.risk_level.value}")
        print(f"  Is Phishing: {result.is_phishing}")
        print(f"  Confidence: {result.confidence}")
        print(f"  Processing Time: {result.processing_time_ms}ms")
        
        if result.findings:
            print(f"\nFindings:")
            for finding in result.findings:
                print(f"  - {finding}")
        
        if result.explanations:
            print(f"\nExplanations:")
            for exp in result.explanations[:3]:
                print(f"  - {exp.get('reason', 'N/A')}")
