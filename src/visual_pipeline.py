"""
Visual Pipeline - CNN-based Screenshot Analysis

This module handles:
1. Brand template comparison
2. Similarity scoring using CNN embeddings
3. Impersonation detection through visual analysis
"""

import os
import logging
from typing import Optional, Dict, Any, List
from pathlib import Path
import numpy as np

logger = logging.getLogger(__name__)

# Try to import deep learning dependencies
try:
    import torch
    import torch.nn as nn
    import torchvision.transforms as transforms
    from PIL import Image
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not available. Install with: pip install torch torchvision")


class VisualInspector:
    """
    CNN-based visual inspection for phishing detection.
    
    Features:
    - Brand template comparison
    - Cosine similarity scoring
    - Impersonation detection
    """
    
    def __init__(
        self,
        model: Optional[nn.Module] = None,
        brand_template_path: Optional[str] = None,
        device: str = 'cpu',
        threshold: float = 0.85
    ):
        """
        Initialize the Visual Inspector.
        
        Args:
            model: CNN model for feature extraction (defaults to ResNet18)
            brand_template_path: Path to brand template image
            device: Computation device ('cpu' or 'cuda')
            threshold: Similarity threshold for impersonation detection
        """
        self.device = device
        self.threshold = threshold
        self.model = model
        self.brand_template = None
        self.brand_name = None
        self.transform = None
        
        # Preprocessing for CNN (ImageNet stats) - only if torch is available
        if TORCH_AVAILABLE:
            self.transform = transforms.Compose([
                transforms.Resize((224, 224)),
                transforms.ToTensor(),
                transforms.Normalize(
                    mean=[0.485, 0.456, 0.406],
                    std=[0.229, 0.224, 0.225]
                )
            ])
        
        # Initialize model if not provided
        if self.model is None and TORCH_AVAILABLE:
            self._init_default_model()
        
        # Load brand template if provided
        if brand_template_path:
            self.load_brand_template(brand_template_path)
    
    def _init_default_model(self) -> None:
        """Initialize default ResNet18 feature extractor."""
        try:
            import torchvision.models as models
            
            # Load pretrained ResNet18
            resnet = models.resnet18(pretrained=True)
            
            # Remove final classification layer to get features
            self.model = nn.Sequential(*list(resnet.children())[:-1])
            self.model.eval()
            self.model.to(self.device)
            
            logger.info("Initialized ResNet18 feature extractor")
            
        except Exception as e:
            logger.error(f"Failed to initialize default model: {e}")
            # Create a simple fallback model
            self.model = nn.Identity()
    
    def load_brand_template(self, template_path: str, brand_name: str = None) -> bool:
        """
        Load a brand template for comparison.
        
        Args:
            template_path: Path to the brand template image
            brand_name: Name of the brand
            
        Returns:
            True if loaded successfully
        """
        if not os.path.exists(template_path):
            logger.warning(f"Brand template not found: {template_path}")
            return False
        
        try:
            self.brand_template = self._load_image(template_path)
            self.brand_name = brand_name or os.path.splitext(os.path.basename(template_path))[0]
            logger.info(f"Loaded brand template: {self.brand_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to load brand template: {e}")
            return False
    
    def _load_image(self, path: str) -> torch.Tensor:
        """Load and preprocess an image."""
        img = Image.open(path).convert('RGB')
        return self.transform(img).unsqueeze(0).to(self.device)
    
    def extract_features(self, image_path: str) -> Optional[np.ndarray]:
        """
        Extract CNN features from an image.
        
        Args:
            image_path: Path to the image
            
        Returns:
            Feature vector or None if failed
        """
        if self.model is None:
            logger.warning("No model available for feature extraction")
            return None
        
        try:
            img_tensor = self._load_image(image_path)
            
            with torch.no_grad():
                features = self.model(img_tensor)
                # Flatten the features
                features = features.squeeze().cpu().numpy()
            
            return features
            
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return None
    
    def calculate_similarity(
        self, 
        screenshot_path: str, 
        template_path: Optional[str] = None
    ) -> float:
        """
        Calculate cosine similarity between screenshot and brand template.
        
        Args:
            screenshot_path: Path to the live screenshot
            template_path: Optional template override
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        # Use provided template or loaded template
        template = None
        
        if template_path:
            try:
                template = self._load_image(template_path)
            except Exception as e:
                logger.error(f"Failed to load template: {e}")
                return 0.0
        elif self.brand_template is not None:
            template = self.brand_template
        else:
            logger.warning("No brand template available")
            return 0.0
        
        if self.model is None:
            logger.warning("No model available for similarity calculation")
            return 0.0
        
        try:
            # Load screenshot
            screenshot = self._load_image(screenshot_path)
            
            with torch.no_grad():
                # Extract features
                embedding_screenshot = self.model(screenshot)
                embedding_template = self.model(template)
                
                # Calculate cosine similarity
                cos = nn.CosineSimilarity(dim=1, eps=1e-6)
                sim_score = cos(embedding_screenshot, embedding_template)
            
            return sim_score.item()
            
        except Exception as e:
            logger.error(f"Similarity calculation failed: {e}")
            return 0.0
    
    def detect_impersonation(
        self, 
        screenshot_path: str,
        threshold: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Detect brand impersonation through visual comparison.
        
        Args:
            screenshot_path: Path to the screenshot
            threshold: Optional threshold override
            
        Returns:
            Dictionary with detection results
        """
        threshold = threshold or self.threshold
        
        if self.brand_template is None:
            return {
                'visual_match_score': 0.0,
                'is_impersonation': False,
                'confidence': 0.0,
                'brand': self.brand_name,
                'error': 'No brand template loaded'
            }
        
        score = self.calculate_similarity(screenshot_path)
        
        # Logic:
        # High similarity = Good (Legit brand page)
        # Low similarity = Bad (Could be phishing or generic page)
        # 
        # Note: High-quality phishing sites may have HIGH similarity
        # (they copy the real site exactly). The key is detecting
        # when the visual LOOKS like a brand but the URL is different.
        
        is_impersonation = score < threshold
        
        return {
            'visual_match_score': round(score, 4),
            'is_impersonation': is_impersonation,
            'confidence': round(abs(score - threshold), 4),
            'brand': self.brand_name,
            'threshold': threshold,
            'interpretation': self._interpret_score(score)
        }
    
    def _interpret_score(self, score: float) -> str:
        """Interpret the similarity score."""
        if score >= 0.95:
            return "Very high similarity - likely authentic brand page"
        elif score >= 0.85:
            return "High similarity - possibly authentic or high-quality clone"
        elif score >= 0.70:
            return "Moderate similarity - may be impersonating brand"
        elif score >= 0.50:
            return "Low similarity - likely not related to brand"
        else:
            return "Very low similarity - unrelated content"
    
    def analyze_multiple_brands(
        self, 
        screenshot_path: str, 
        brand_templates: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Analyze screenshot against multiple brand templates.
        
        Args:
            screenshot_path: Path to screenshot
            brand_templates: Dict mapping brand name to template path
            
        Returns:
            Analysis results for all brands
        """
        results = {
            'screenshot': screenshot_path,
            'brands_analyzed': [],
            'best_match': None,
            'highest_score': 0.0
        }
        
        for brand_name, template_path in brand_templates.items():
            # Temporarily load this template
            old_template = self.brand_template
            old_name = self.brand_name
            
            self.load_brand_template(template_path, brand_name)
            result = self.detect_impersonation(screenshot_path)
            
            results['brands_analyzed'].append({
                'brand': brand_name,
                'score': result['visual_match_score'],
                'is_impersonation': result['is_impersonation']
            })
            
            if result['visual_match_score'] > results['highest_score']:
                results['highest_score'] = result['visual_match_score']
                results['best_match'] = brand_name
            
            # Restore original template
            self.brand_template = old_template
            self.brand_name = old_name
        
        return results


class BrandTemplateManager:
    """
    Manager for brand templates.
    
    Handles:
    - Template storage and retrieval
    - Automatic template loading
    """
    
    def __init__(self, template_dir: Optional[str] = None):
        """
        Initialize the template manager.
        
        Args:
            template_dir: Directory containing brand templates
        """
        self.template_dir = template_dir
        self.templates: Dict[str, str] = {}
        
        if template_dir and os.path.exists(template_dir):
            self._discover_templates()
    
    def _discover_templates(self) -> None:
        """Auto-discover templates in the template directory."""
        supported_formats = ['.jpg', '.jpeg', '.png', '.webp']
        
        for filename in os.listdir(self.template_dir):
            ext = os.path.splitext(filename)[1].lower()
            if ext in supported_formats:
                brand_name = os.path.splitext(filename)[0]
                self.templates[brand_name] = os.path.join(
                    self.template_dir, 
                    filename
                )
        
        logger.info(f"Discovered {len(self.templates)} brand templates")
    
    def get_template_path(self, brand_name: str) -> Optional[str]:
        """Get template path for a brand."""
        return self.templates.get(brand_name.lower())
    
    def list_brands(self) -> List[str]:
        """List all available brands."""
        return list(self.templates.keys())


# Factory function
def create_visual_inspector(
    model_path: Optional[str] = None,
    brand_template_path: Optional[str] = None,
    device: str = 'cpu'
) -> VisualInspector:
    """
    Create a VisualInspector instance.
    
    Args:
        model_path: Path to custom CNN model
        brand_template_path: Path to brand template
        device: Computation device
        
    Returns:
        VisualInspector instance
    """
    model = None
    
    if model_path and TORCH_AVAILABLE:
        try:
            model = torch.load(model_path, map_location=device)
            logger.info(f"Loaded custom model from {model_path}")
        except Exception as e:
            logger.warning(f"Could not load custom model: {e}")
    
    return VisualInspector(
        model=model,
        brand_template_path=brand_template_path,
        device=device
    )


if __name__ == "__main__":
    # Demo/test the visual inspector
    inspector = create_visual_inspector()
    
    print("Visual Inspector initialized")
    print(f"Device: {inspector.device}")
    print(f"Model type: {type(inspector.model).__name__ if inspector.model else 'None'}")
    print(f"Threshold: {inspector.threshold}")
    
    # Test with dummy image if available
    test_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    if os.path.exists(test_dir):
        print(f"\nTest directory contents: {os.listdir(test_dir)}")
