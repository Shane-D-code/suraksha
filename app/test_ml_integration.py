
import asyncio
import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.curdir))

from app.services.threat_graph_engine import ThreatGraphEngine
from app.services import database as db_service
from app.services.redis import get_redis_client

async def test_gnn():
    print("Testing GNN loading and inference...")
    try:
        # Initialize DB and Redis
        await db_service.init_db()
        redis_client = await get_redis_client()
        
        engine = ThreatGraphEngine(db_pool=db_service.db_pool, redis_client=redis_client)
        
        print("Starting engine...")
        await engine.startup()
        print("Engine started.")
        
        domain = "secure-login-paypal.com"
        print(f"Analyzing domain: {domain}")
        result = await engine.analyze(domain)
        
        print(f"Result for {domain}:")
        print(f"  GNN Score: {result.gnn_score}")
        print(f"  Cluster Prob: {result.cluster_probability}")
        print(f"  In Campaign: {result.in_campaign}")
        
        if result.gnn_score > 0:
            print("✅ GNN Inference successful!")
        else:
            print("⚠️ GNN Score is 0. Check if model is loaded correctly.")
            
    except Exception as e:
        print(f"❌ GNN Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_gnn())
