"""Test script to verify torch_geometric and GNN are working."""

import sys
import asyncio

# Test 1: Check torch_geometric import
print("=" * 50)
print("Test 1: Checking torch_geometric import...")
try:
    import torch_geometric
    print(f"✅ torch_geometric version: {torch_geometric.__version__}")
except ImportError as e:
    print(f"❌ torch_geometric not available: {e}")

# Test 2: Check torch
print("=" * 50)
print("Test 2: Checking torch...")
import torch
print(f"✅ PyTorch version: {torch.__version__}")

# Test 3: Test the embedding service
print("=" * 50)
print("Test 3: Testing EmbeddingService...")
sys.path.insert(0, '.')

from app.services.embedding_service import EmbeddingService, TORCH_GEOMETRIC_AVAILABLE

print(f"✅ TORCH_GEOMETRIC_AVAILABLE: {TORCH_GEOMETRIC_AVAILABLE}")

# Create embedding service
service = EmbeddingService(model_path="ml/models/gnn_model.pt")

# Initialize
asyncio.run(service.initialize())

print(f"✅ EmbeddingService initialized")
print(f"✅ Model loaded: {service.model is not None}")

# Test embedding generation
async def test_embedding():
    emb, score = await service.get_embedding("example.com")
    print(f"✅ Generated embedding for 'example.com'")
    print(f"   Embedding shape: {emb.shape}")
    print(f"   Score: {score}")
    return emb, score

asyncio.run(test_embedding())

# Test 4: Test threat graph engine
print("=" * 50)
print("Test 4: Testing ThreatGraphEngine...")

from app.services.threat_graph_engine import ThreatGraphEngine

# Create engine (minimal)
class MockDB:
    pass

engine = ThreatGraphEngine(db_pool=MockDB(), redis_client=None)

print("✅ ThreatGraphEngine created")

# Try startup (may fail if no DB, but should load GNN)
try:
    await engine.startup()
    print("✅ ThreatGraphEngine started successfully")
except Exception as e:
    print(f"⚠️ ThreatGraphEngine startup failed (expected without DB): {e}")

print("=" * 50)
print("All tests completed!")
