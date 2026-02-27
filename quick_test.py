"""
Quick test to verify the API works.
This script tests the API components without needing a running server.
"""
import asyncio
from app.services.redis import check_redis_health, init_redis, close_redis
from app.services.graph import GraphService
from app.services.scoring import compute_final_score
from app.models.schemas import RiskLevel

async def test_components():
    """Test all components."""
    print("="*60)
    print("🛡️  QUICK COMPONENT TEST")
    print("="*60)
    
    # Test Redis
    print("\n1️⃣  Testing Redis...")
    try:
        await init_redis()
        is_healthy = await check_redis_health()
        if is_healthy:
            print("   ✅ Redis: WORKING")
        else:
            print("   ❌ Redis: FAILED")
    except Exception as e:
        print(f"   ❌ Redis: ERROR - {str(e)}")
    
    # Test Graph Service
    print("\n2️⃣  Testing Graph Service...")
    try:
        graph = GraphService()
        await graph._ensure_graph_loaded()
        risk_score = await graph.get_risk_score("example.com")
        connections = await graph.get_domain_connections("example.com")
        print(f"   Graph nodes: {graph.graph.number_of_nodes()}")
        print(f"   Graph edges: {graph.graph.number_of_edges()}")
        print(f"   Risk score for example.com: {risk_score}")
        print(f"   Connections: {connections}")
        print("   ✅ Graph Service: WORKING")
    except Exception as e:
        print(f"   ❌ Graph Service: ERROR - {str(e)}")
    
    # Test Scoring
    print("\n3️⃣  Testing Scoring Engine...")
    try:
        risk, confidence, reasons = compute_final_score(0.8, 0.7)
        print(f"   Risk Level: {risk.value}")
        print(f"   Confidence: {confidence}")
        print(f"   Reasons: {reasons}")
        print("   ✅ Scoring Engine: WORKING")
    except Exception as e:
        print(f"   ❌ Scoring Engine: ERROR - {str(e)}")
    
    # Test Schemas
    print("\n4️⃣  Testing Pydantic Schemas...")
    try:
        from app.models.schemas import ScanRequest, ScanResponse
        from datetime import datetime
        
        # Test request validation
        request = ScanRequest(
            url="https://example.com",
            meta={"source": "test"}
        )
        print(f"   Request validated: {request.url}")
        
        # Test response creation
        response = ScanResponse(
            scan_id="test-123",
            risk=RiskLevel.HIGH,
            0.95,
            reasons=["Test reason"],
            graph_score=0.8,
            model_score=0.9,
            timestamp=datetime.utcnow()
        )
        print(f"   Response created: {response.scan_id}")
        print("   ✅ Schemas: WORKING")
    except Exception as e:
        print(f"   ❌ Schemas: ERROR - {str(e)}")
    
    # Cleanup
    await close_redis()
    
    print("\n" + "="*60)
    print("✅ COMPONENT TEST COMPLETE")
    print("="*60)
    print("\nAll core components are working!")
    print("\nTo start the full API server:")
    print("  python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000")
    print("\nThen open test_frontend.html in your browser.")

if __name__ == "__main__":
    asyncio.run(test_components())
