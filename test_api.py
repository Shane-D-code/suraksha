"""
Comprehensive API test script for Threat Intelligence Platform.
"""
import asyncio
import httpx
import json
from datetime import datetime

BASE_URL = "http://localhost:8000"

async def test_health():
    """Test health endpoint."""
    print("\n" + "="*60)
    print("Testing Health Endpoint")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/health")
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        assert response.status_code == 200
        print("✅ Health check passed")

async def test_root():
    """Test root endpoint."""
    print("\n" + "="*60)
    print("Testing Root Endpoint")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/")
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        assert response.status_code == 200
        print("✅ Root endpoint passed")

async def test_scan_url():
    """Test scan endpoint with URL."""
    print("\n" + "="*60)
    print("Testing Scan Endpoint (URL)")
    print("="*60)
    
    payload = {
        "url": "https://example.com",
        "meta": {"source": "test_script"}
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BASE_URL}/api/v1/scan",
            json=payload,
            timeout=30.0
        )
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        
        assert response.status_code == 200
        assert "scan_id" in data
        assert "risk" in data
        assert "confidence" in data
        print("✅ Scan URL test passed")
        return data["scan_id"]

async def test_scan_text():
    """Test scan endpoint with text."""
    print("\n" + "="*60)
    print("Testing Scan Endpoint (Text)")
    print("="*60)
    
    payload = {
        "text": "Click here to verify your account: http://phishing-site.com",
        "meta": {"source": "test_script"}
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BASE_URL}/api/v1/scan",
            json=payload,
            timeout=30.0
        )
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        
        assert response.status_code == 200
        print("✅ Scan text test passed")
        return data["scan_id"]

async def test_feedback(scan_id):
    """Test feedback endpoint."""
    print("\n" + "="*60)
    print("Testing Feedback Endpoint")
    print("="*60)
    
    payload = {
        "scan_id": scan_id,
        "user_flag": True,
        "corrected_label": "HIGH",
        "comment": "This is a test feedback"
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BASE_URL}/api/v1/feedback",
            json=payload,
            timeout=30.0
        )
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        
        assert response.status_code == 200
        assert "feedback_id" in data
        print("✅ Feedback test passed")

async def test_threat_intel():
    """Test threat intel endpoint."""
    print("\n" + "="*60)
    print("Testing Threat Intel Endpoint")
    print("="*60)
    
    domain = "example.com"
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{BASE_URL}/api/v1/threat-intel/{domain}",
            timeout=30.0
        )
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        
        assert response.status_code == 200
        assert "domain" in data
        assert "risk_score" in data
        print("✅ Threat intel test passed")

async def test_model_health():
    """Test model health endpoint."""
    print("\n" + "="*60)
    print("Testing Model Health Endpoint")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{BASE_URL}/api/v1/model-health",
            timeout=30.0
        )
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Response: {json.dumps(data, indent=2)}")
        
        assert response.status_code == 200
        assert "model_name" in data
        print("✅ Model health test passed")

async def test_cache():
    """Test caching functionality."""
    print("\n" + "="*60)
    print("Testing Cache Functionality")
    print("="*60)
    
    payload = {
        "url": "https://cache-test.com",
        "meta": {"source": "cache_test"}
    }
    
    async with httpx.AsyncClient() as client:
        # First request
        start1 = datetime.now()
        response1 = await client.post(
            f"{BASE_URL}/api/v1/scan",
            json=payload,
            timeout=30.0
        )
        time1 = (datetime.now() - start1).total_seconds()
        
        # Second request (should be cached)
        start2 = datetime.now()
        response2 = await client.post(
            f"{BASE_URL}/api/v1/scan",
            json=payload,
            timeout=30.0
        )
        time2 = (datetime.now() - start2).total_seconds()
        
        print(f"First request time: {time1:.3f}s")
        print(f"Second request time: {time2:.3f}s")
        print(f"Speed improvement: {(time1/time2):.2f}x")
        
        assert response1.status_code == 200
        assert response2.status_code == 200
        assert response1.json()["scan_id"] == response2.json()["scan_id"]
        print("✅ Cache test passed")

async def run_all_tests():
    """Run all tests."""
    print("\n" + "="*60)
    print("🛡️  THREAT INTELLIGENCE PLATFORM - API TESTS")
    print("="*60)
    print(f"Base URL: {BASE_URL}")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # Basic tests
        await test_health()
        await test_root()
        
        # Scan tests
        scan_id1 = await test_scan_url()
        scan_id2 = await test_scan_text()
        
        # Feedback test
        await test_feedback(scan_id1)
        
        # Intel tests
        await test_threat_intel()
        await test_model_health()
        
        # Performance test
        await test_cache()
        
        print("\n" + "="*60)
        print("✅ ALL TESTS PASSED!")
        print("="*60)
        
    except Exception as e:
        print("\n" + "="*60)
        print(f"❌ TEST FAILED: {str(e)}")
        print("="*60)
        raise

if __name__ == "__main__":
    asyncio.run(run_all_tests())
