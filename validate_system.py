"""
System validation script - checks all components.
"""
import asyncio
import sys
from app.services.database import check_database_health
from app.services.redis import check_redis_health
from app.config import settings

async def validate_config():
    """Validate configuration."""
    print("\n📋 Validating Configuration...")
    print(f"  App Name: {settings.APP_NAME}")
    print(f"  Version: {settings.APP_VERSION}")
    print(f"  Debug Mode: {settings.DEBUG}")
    print(f"  API Prefix: {settings.API_PREFIX}")
    print(f"  Database URL: {settings.DATABASE_URL.split('@')[-1]}")
    print(f"  Redis URL: {settings.REDIS_URL}")
    print("  ✅ Configuration loaded")

async def validate_database():
    """Validate database connection."""
    print("\n🗄️  Validating Database...")
    try:
        is_healthy = await check_database_health()
        if is_healthy:
            print("  ✅ Database connection successful")
            return True
        else:
            print("  ❌ Database connection failed")
            return False
    except Exception as e:
        print(f"  ❌ Database error: {str(e)}")
        return False

async def validate_redis():
    """Validate Redis connection."""
    print("\n🔴 Validating Redis...")
    try:
        is_healthy = await check_redis_health()
        if is_healthy:
            print("  ✅ Redis connection successful")
            return True
        else:
            print("  ❌ Redis connection failed")
            return False
    except Exception as e:
        print(f"  ❌ Redis error: {str(e)}")
        return False

async def validate_graph():
    """Validate graph service."""
    print("\n🕸️  Validating Graph Service...")
    try:
        from app.services.graph import GraphService
        graph = GraphService()
        await graph._ensure_graph_loaded()
        print(f"  Graph nodes: {graph.graph.number_of_nodes()}")
        print(f"  Graph edges: {graph.graph.number_of_edges()}")
        print("  ✅ Graph service initialized")
        return True
    except Exception as e:
        print(f"  ❌ Graph error: {str(e)}")
        return False

async def validate_scoring():
    """Validate scoring service."""
    print("\n🎯 Validating Scoring Service...")
    try:
        from app.services.scoring import compute_final_score
        risk, confidence, reasons = compute_final_score(0.8, 0.7)
        print(f"  Test score - Risk: {risk.value}, Confidence: {confidence}")
        print(f"  Reasons: {len(reasons)} generated")
        print("  ✅ Scoring service working")
        return True
    except Exception as e:
        print(f"  ❌ Scoring error: {str(e)}")
        return False

async def main():
    """Run all validations."""
    print("="*60)
    print("🛡️  THREAT INTELLIGENCE PLATFORM - SYSTEM VALIDATION")
    print("="*60)
    
    results = []
    
    # Run validations
    await validate_config()
    results.append(("Database", await validate_database()))
    results.append(("Redis", await validate_redis()))
    results.append(("Graph", await validate_graph()))
    results.append(("Scoring", await validate_scoring()))
    
    # Summary
    print("\n" + "="*60)
    print("📊 VALIDATION SUMMARY")
    print("="*60)
    
    for name, status in results:
        status_icon = "✅" if status else "❌"
        print(f"  {status_icon} {name}: {'PASS' if status else 'FAIL'}")
    
    all_passed = all(status for _, status in results)
    
    print("\n" + "="*60)
    if all_passed:
        print("✅ ALL VALIDATIONS PASSED - System is ready!")
        print("="*60)
        print("\nNext steps:")
        print("  1. Start the server: python -m uvicorn app.main:app --reload")
        print("  2. Open test frontend: test_frontend.html")
        print("  3. Run API tests: python test_api.py")
        return 0
    else:
        print("❌ SOME VALIDATIONS FAILED - Please fix errors above")
        print("="*60)
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
