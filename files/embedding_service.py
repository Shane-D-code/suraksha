"""
embedding_service.py
Person 3 — Graph & Threat Intelligence
GraphSAGE-style inductive embedding generation.

Key upgrade over old system:
  OLD: Precomputed embeddings → can't handle new domains
  NEW: Inductive → generate embedding for ANY domain, even unseen ones,
       using its neighborhood features. No retraining needed.
"""

import asyncio
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import networkx as nx
import logging
import json
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)

EMBEDDING_DIM = 64
FEATURE_DIM = 16  # raw node feature size


# ─── Feature Extraction ──────────────────────────────────────────────────────

def extract_node_features(domain: str, node_data: dict) -> torch.Tensor:
    """
    Converts raw node attributes into a fixed-size feature vector.
    Works for ANY domain — even ones never seen during training.
    That's what makes this inductive.
    """
    features = []

    # 1. Domain string features
    features.append(len(domain))                           # length
    features.append(domain.count("."))                     # subdomain depth
    features.append(domain.count("-"))                     # hyphens (phishing signal)
    features.append(sum(c.isdigit() for c in domain))     # digit count

    # 2. TLD risk signal
    RISKY_TLDS = {".xyz": 1.0, ".tk": 1.0, ".ml": 1.0, ".ga": 1.0,
                  ".cf": 1.0, ".gq": 1.0, ".top": 0.8, ".click": 0.8,
                  ".com": 0.1, ".org": 0.1, ".edu": 0.0}
    tld_risk = 0.5  # unknown
    for tld, score in RISKY_TLDS.items():
        if domain.endswith(tld):
            tld_risk = score
            break
    features.append(tld_risk)

    # 3. Graph-derived features (from node metadata)
    features.append(1.0 if node_data.get("ip") else 0.0)
    features.append(1.0 if node_data.get("ssl_fingerprint") else 0.0)
    features.append(float(node_data.get("gnn_score", 0.0)))

    # 4. Structural features (filled after neighborhood aggregation)
    features.append(0.0)   # degree placeholder
    features.append(0.0)   # neighbor malicious ratio placeholder
    features.append(0.0)   # shared IP flag placeholder
    features.append(0.0)   # shared cert flag placeholder

    # Padding to FEATURE_DIM
    while len(features) < FEATURE_DIM:
        features.append(0.0)

    tensor = torch.tensor(features[:FEATURE_DIM], dtype=torch.float32)

    # Normalize so large values don't dominate
    tensor[0] = tensor[0] / 100.0   # domain length
    tensor[1] = tensor[1] / 5.0     # subdomain depth
    tensor[2] = tensor[2] / 10.0    # hyphens
    tensor[3] = tensor[3] / 10.0    # digits

    return tensor


# ─── GraphSAGE Model ─────────────────────────────────────────────────────────

class GraphSAGELayer(nn.Module):
    """
    One layer of GraphSAGE:
      1. Aggregate neighbor features (mean pooling)
      2. Concatenate with self features
      3. Apply linear transform + activation

    Why mean pooling: simple, fast, works well for variable-size neighborhoods.
    """

    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        self.self_linear = nn.Linear(in_dim, out_dim)
        self.neighbor_linear = nn.Linear(in_dim, out_dim)
        self.norm = nn.LayerNorm(out_dim)

    def forward(self, self_feat: torch.Tensor, neighbor_feats: torch.Tensor) -> torch.Tensor:
        # neighbor_feats: (num_neighbors, in_dim) or (1, in_dim) if no neighbors
        neighbor_agg = neighbor_feats.mean(dim=0)  # mean pooling
        out = self.self_linear(self_feat) + self.neighbor_linear(neighbor_agg)
        return F.relu(self.norm(out))


class InductiveGNN(nn.Module):
    """
    2-layer GraphSAGE.
    Layer 1: raw features → hidden
    Layer 2: hidden → embedding

    Inductive means: given a new node's features + its neighbors' features,
    we can generate its embedding without retraining.
    """

    def __init__(self, feature_dim: int = FEATURE_DIM,
                 hidden_dim: int = 32,
                 embedding_dim: int = EMBEDDING_DIM):
        super().__init__()
        self.layer1 = GraphSAGELayer(feature_dim, hidden_dim)
        self.layer2 = GraphSAGELayer(hidden_dim, embedding_dim)
        self.dropout = nn.Dropout(0.3)

    def forward(self, node_feat: torch.Tensor,
                neighbor_feats_l1: torch.Tensor,
                neighbor_feats_l2: torch.Tensor) -> torch.Tensor:
        h1 = self.layer1(node_feat, neighbor_feats_l1)
        h1 = self.dropout(h1)
        h2 = self.layer2(h1, neighbor_feats_l2)
        return F.normalize(h2, dim=0)  # L2 normalize for cosine similarity


# ─── Embedding Service ───────────────────────────────────────────────────────

class EmbeddingService:
    """
    Generates and caches domain embeddings using InductiveGNN.

    Flow:
      1. Extract node features for target domain
      2. Extract features for 1-hop neighbors
      3. Extract features for 2-hop neighbors
      4. Run through InductiveGNN
      5. Cache result in Redis (1hr TTL)
      6. Return 64-dim embedding vector

    New domains work immediately — no retraining required.
    """

    def __init__(self, model_path: str = "ml/models/gnn_model.pt",
                 graph=None, redis_client=None):
        self.model_path = Path(model_path)
        self.graph: Optional[nx.DiGraph] = graph
        self.redis = redis_client
        self.model: Optional[InductiveGNN] = None
        self.device = torch.device("cpu")  # CPU fine for inference

    async def initialize(self):
        """Load or create model."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._load_or_create_model)
        logger.info("EmbeddingService initialized")

    def _load_or_create_model(self):
        if self.model_path.exists():
            self.model = InductiveGNN()
            self.model.load_state_dict(
                torch.load(self.model_path, map_location=self.device)
            )
            logger.info(f"Loaded GNN from {self.model_path}")
        else:
            logger.warning("No saved model found — using untrained model. "
                           "Run training before production use.")
            self.model = InductiveGNN()

        self.model.eval()

    def set_graph(self, graph: nx.DiGraph):
        """Hot-swap the graph when it updates."""
        self.graph = graph

    # ── Embedding Generation ──────────────────────────────────────────────────

    async def get_embedding(self, domain: str) -> np.ndarray:
        """
        Main entry point. Returns 64-dim numpy array.
        Checks Redis cache first, generates if miss.
        """
        # Cache check
        if self.redis:
            cached = await self.redis.get(f"embedding:{domain}")
            if cached:
                return np.frombuffer(cached, dtype=np.float32)

        embedding = await asyncio.get_event_loop().run_in_executor(
            None, self._generate_embedding, domain
        )

        # Cache for 1 hour
        if self.redis:
            await self.redis.setex(
                f"embedding:{domain}", 3600,
                embedding.astype(np.float32).tobytes()
            )

        return embedding

    def _generate_embedding(self, domain: str) -> np.ndarray:
        """Synchronous embedding generation (runs in executor)."""
        if self.model is None:
            raise RuntimeError("Model not initialized. Call initialize() first.")

        if self.graph is None:
            # No graph yet — use feature-only embedding
            return self._feature_only_embedding(domain)

        node_data = self.graph.nodes.get(domain, {})
        node_feat = extract_node_features(domain, node_data)

        # 1-hop neighbors
        neighbors_1 = self._get_neighbor_features(domain, depth=1)

        # 2-hop neighbors (neighbors of neighbors)
        neighbors_2 = self._get_neighbor_features(domain, depth=2)

        with torch.no_grad():
            embedding = self.model(node_feat, neighbors_1, neighbors_2)

        return embedding.numpy()

    def _get_neighbor_features(self, domain: str, depth: int) -> torch.Tensor:
        """
        Collects neighbor feature tensors at a given hop depth.
        Returns (N, FEATURE_DIM) tensor. Falls back to zero if no neighbors.
        """
        if self.graph is None or domain not in self.graph:
            return torch.zeros(1, FEATURE_DIM)

        if depth == 1:
            nodes = list(self.graph.neighbors(domain))
        else:
            # 2-hop: neighbors of neighbors
            nodes = []
            for n in self.graph.neighbors(domain):
                nodes.extend(list(self.graph.neighbors(n)))
            nodes = list(set(nodes) - {domain})

        if not nodes:
            return torch.zeros(1, FEATURE_DIM)

        feats = [
            extract_node_features(n, self.graph.nodes.get(n, {}))
            for n in nodes[:20]  # cap at 20 neighbors for speed
        ]
        return torch.stack(feats)

    def _feature_only_embedding(self, domain: str) -> np.ndarray:
        """Fallback: generate embedding from features alone when no graph."""
        feat = extract_node_features(domain, {})
        # Project to embedding dim with a simple linear layer
        with torch.no_grad():
            proj = nn.Linear(FEATURE_DIM, EMBEDDING_DIM)
            result = F.normalize(proj(feat), dim=0)
        return result.numpy()

    # ── Batch Generation ──────────────────────────────────────────────────────

    async def get_batch_embeddings(self, domains: list[str]) -> dict[str, np.ndarray]:
        """Generate embeddings for multiple domains concurrently."""
        tasks = [self.get_embedding(d) for d in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return {
            domain: emb
            for domain, emb in zip(domains, results)
            if isinstance(emb, np.ndarray)
        }

    # ── Model Persistence ─────────────────────────────────────────────────────

    def save_model(self):
        """Save current model weights."""
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(self.model.state_dict(), self.model_path)
        logger.info(f"Model saved to {self.model_path}")
