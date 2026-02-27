"""
Test script for PhishGuard Modular Architecture

This script tests the ONNX, Visual, SHAP pipelines and the Fusion Engine.
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all modules can be imported."""
    print("Testing imports...")
    
    try:
        from src import ONNXPipeline, VisualInspector, ExplainerEngine, PhishingFusionEngine
        print("  ✓ All modules imported successfully")
        return True
    except ImportError as e:
        print(f"  ✗ Import failed: {e}")
        return False


def test_onnx_pipeline():
    """Test ONNX pipeline."""
    print("\nTesting ONNX Pipeline...")
    
    try:
        from src.onnx_pipeline import create_onnx_pipeline
        
        # Create pipeline
        pipeline = create_onnx_pipeline(
            model_dir=os.path.join(os.path.dirname(__file__), 'models'),
            model_name='phish_model.joblib'
        )
        
        print(f"  ✓ Pipeline created: {type(pipeline).__name__}")
        print(f"  ✓ Model type: {pipeline._model_type}")
        
        # Test feature extraction
        test_text = "Urgent: Verify your account immediately!"
        features = pipeline.extract_features(test_text)
        print(f"  ✓ Feature extraction: shape = {features.shape}")
        
        # Test prediction
        result = pipeline.predict(features)
        print(f"  ✓ Prediction: {result}")
        
        return True
        
    except Exception as e:
        print(f"  ✗ ONNX pipeline test failed: {e}")
        return False


def test_visual_pipeline():
    """Test Visual pipeline."""
    print("\nTesting Visual Pipeline...")
    
    try:
        from src.visual_pipeline import create_visual_inspector
        
        # Create inspector
        inspector = create_visual_inspector()
        
        print(f"  ✓ Visual inspector created: {type(inspector).__name__}")
        print(f"  ✓ Device: {inspector.device}")
        print(f"  ✓ Threshold: {inspector.threshold}")
        
        # Test with no template (should return safe defaults)
        print(f"  ✓ Brand template loaded: {inspector.brand_template is not None}")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Visual pipeline test failed: {e}")
        return False


def test_shap_pipeline():
    """Test SHAP pipeline."""
    print("\nTesting SHAP Pipeline...")
    
    try:
        from src.shap_pipeline import create_explainer
        
        # Create explainer
        explainer = create_explainer()
        
        print(f"  ✓ Explainer created: {type(explainer).__name__}")
        print(f"  ✓ Model type: {explainer._model_type}")
        
        # Test with sample features
        sample_features = {
            'url_length': 85,
            'num_subdomains': 4,
            'urgency_score': 0.8,
            'brand_detected': 1,
            'login_form': 1,
            'suspicious_tld': 1
        }
        
        result = explainer.explain_prediction(sample_features, top_n=5)
        print(f"  ✓ Explanation generated")
        print(f"  ✓ Reasons count: {len(result.get('reasons', []))}")
        
        return True
        
    except Exception as e:
        print(f"  ✗ SHAP pipeline test failed: {e}")
        return False


def test_fusion_engine():
    """Test Fusion Engine."""
    print("\nTesting Fusion Engine...")
    
    try:
        from src.fusion_engine import create_fusion_engine
        
        # Create engine
        engine = create_fusion_engine(
            model_dir=os.path.join(os.path.dirname(__file__), 'models')
        )
        
        print(f"  ✓ Fusion engine created")
        print(f"  ✓ NLP Pipeline: {type(engine.nlp_pipeline).__name__}")
        print(f"  ✓ Visual Inspector: {type(engine.visual_inspector).__name__}")
        print(f"  ✓ SHAP Explainer: {type(engine.shap_explainer).__name__}")
        
        # Test analysis
        test_cases = [
            {
                'text': "Your account has been suspended. Verify now to avoid closure!",
                'url': "https://paypal-verify-account.xyz/login"
            },
            {
                'text': "Welcome to our website, how can I help you?",
                'url': "https://www.example.com"
            }
        ]
        
        for i, test in enumerate(test_cases):
            result = engine.analyze(
                text=test.get('text'),
                url=test.get('url')
            )
            print(f"  ✓ Test case {i+1}:")
            print(f"    - Risk Score: {result.risk_score}")
            print(f"    - Risk Level: {result.risk_level.value}")
            print(f"    - Is Phishing: {result.is_phishing}")
            print(f"    - Processing Time: {result.processing_time_ms}ms")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Fusion engine test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_quick_analyze():
    """Test quick analyze function."""
    print("\nTesting quick_analyze...")
    
    try:
        from src.fusion_engine import quick_analyze
        
        result = quick_analyze(
            text="Urgent! Click here to verify your account",
            url="https://paypal-secure-login.xyz"
        )
        
        print(f"  ✓ Quick analysis completed")
        print(f"  ✓ Result: {result.get('risk_level')} (score: {result.get('risk_score')})")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Quick analyze test failed: {e}")
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("PhishGuard Modular Architecture Test Suite")
    print("=" * 60)
    
    tests = [
        ("Imports", test_imports),
        ("ONNX Pipeline", test_onnx_pipeline),
        ("Visual Pipeline", test_visual_pipeline),
        ("SHAP Pipeline", test_shap_pipeline),
        ("Fusion Engine", test_fusion_engine),
        ("Quick Analyze", test_quick_analyze),
    ]
    
    results = []
    
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n  ✗ Test '{name}' crashed: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
