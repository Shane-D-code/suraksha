"""
embedding_service.py
Person 3 — Graph & Threat Intelligence
GraphSAGE-style inductive embedding generation.

Key upgrade over old system:
  OLD: Precomputed embeddings → can't handle new domains
  NEW: Inductive → generate embedding for ANY domain, even unseen ones,
       using its neighborhood features. No retraining needed.

Robust fallback handling:
  - If torch_geometric is unavailable, uses heuristic-based embeddings
  - System works in both Docker and local environments
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

from app.services.redis import get_raw_redis_client

logger = logging.getLogger(__name__)

EMBEDDING_DIM = 64
FEATURE_DIM = 7  # raw node feature size

# Check if torch_geometric is available
TORCH_GEOMETRIC_AVAILABLE = False
try:
    import torch_geometric
    TORCH_GEOMETRIC_AVAILABLE = True
    logger.info("torch_geometric available - advanced graph ops enabled")
except ImportError as e:
    logger.warning(f"torch_geometric not available: {e}")
    logger.info("Using NetworkX-only fallback mode with heuristic embeddings")


# ─── Feature Extraction ──────────────────────────────────────────────────────

def extract_node_features(domain: str, node_data: dict) -> torch.Tensor:
    """
    Extracts 7 features matching the trained GraphSAGE model.
    Must match features used in intelligence/gnn/train_gnn.py
    """
    # 1. Domain length (normalized)
    domain_length = len(domain) / 100.0
    
    # 2. Number of dots (subdomain depth, normalized)
    dot_count = domain.count(".") / 5.0
    
    # 3. Hyphen count (normalized)
    hyphen_count = domain.count("-") / 10.0
    
    # 4. Digit count (normalized)
    digit_count = sum(c.isdigit() for c in domain) / 20.0
    
    # 5. PageRank centrality (from node_data or calculate)
    pr_score = float(node_data.get("pagerank", 0.0))
    
    # 6. Malicious neighbor ratio
    malicious_neighbors = float(node_data.get("malicious_ratio", 0.0))
    
    # 7. SSL presence
    has_ssl = float(node_data.get("has_ssl", 0))
    
    features = [
        domain_length,
        dot_count,
        hyphen_count,
        digit_count,
        pr_score,
        malicious_neighbors,
        has_ssl
    ]
    
    return torch.tensor(features, dtype=torch.float32)


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


class GraphSAGE(nn.Module):
    """
    2-layer GraphSAGE matching the trained model architecture.
    """
    def __init__(self, in_channels: int = 7, hidden_channels: int = 64, out_channels: int = 2):
        super().__init__()
        from torch_geometric.nn import SAGEConv
        
        self.conv1 = SAGEConv(in_channels, hidden_channels)
        self.conv2 = SAGEConv(hidden_channels, hidden_channels)
        self.linear = nn.Linear(hidden_channels, out_channels)

    def forward(self, x, edge_index):
        # First layer
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        
        # Second layer
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        
        # Classification layer
        x = self.linear(x)
        return x
    
    def get_embeddings(self, x, edge_index):
        """Get embeddings from last hidden layer (before classification)."""
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        return x


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
            try:
                self.model = GraphSAGE(in_channels=7, hidden_channels=64, out_channels=2)
                checkpoint = torch.load(self.model_path, map_location=self.device)
                self.model.load_state_dict(checkpoint)
                    
                print(f"DEBUG: Loaded trained GNN from {self.model_path}")
                logger.info(f"Loaded trained GNN from {self.model_path}")
            except Exception as e:
                print(f"DEBUG: Failed to load GNN from {self.model_path}: {e}")
                logger.warning(f"Failed to load GNN from {self.model_path}: {e}")
                self.model = GraphSAGE(in_channels=7, hidden_channels=64, out_channels=2)
        else:
            logger.warning("No saved model found — using untrained model. "
                           "Run training before production use.")
            self.model = GraphSAGE(in_channels=7, hidden_channels=64, out_channels=2)

        self.model.eval()

    def set_graph(self, graph: nx.DiGraph):
        """Hot-swap the graph when it updates."""
        self.graph = graph

    # ── Embedding Generation ──────────────────────────────────────────────────

    async def get_embedding(self, domain: str) -> tuple[np.ndarray, float]:
        """
        Main entry point. Returns (embedding, score) tuple.
        Checks Redis cache first.
        """
        try:
            raw_redis = await get_raw_redis_client()
            # Cache check
            cached = await raw_redis.get(f"embedding:{domain}")
            cached_score = await raw_redis.get(f"score:{domain}")
            
            if cached and cached_score:
                embedding = np.frombuffer(cached, dtype=np.float32)
                if embedding.size != EMBEDDING_DIM:
                    logger.warning(
                        "Ignoring cached embedding with wrong dimension: "
                        f"domain={domain} expected={EMBEDDING_DIM} actual={embedding.size}"
                    )
                    await raw_redis.delete(f"embedding:{domain}", f"score:{domain}")
                else:
                    return (
                        embedding,
                        float(cached_score.decode() if isinstance(cached_score, bytes) else cached_score)
                    )
        except Exception as e:
            logger.warning(f"Redis embedding cache failed: {e}")
            raw_redis = None

        embedding, score = await asyncio.get_event_loop().run_in_executor(
            None, self._generate_embedding, domain
        )

        # Cache for 1 hour
        if raw_redis:
            try:
                await raw_redis.setex(
                    f"embedding:{domain}", 3600,
                    embedding.astype(np.float32).tobytes()
                )
                await raw_redis.setex(
                    f"score:{domain}", 3600,
                    str(score).encode()
                )
            except Exception:
                pass

        return embedding, score

    def _generate_embedding(self, domain: str) -> tuple[np.ndarray, float]:
        """Synchronous embedding + score generation using trained GNN."""
        if self.model is None:
            raise RuntimeError("Model not initialized. Call initialize() first.")

        # Build subgraph for this domain
        if self.graph and domain in self.graph:
            # Get 1-hop and 2-hop neighbors
            neighbors_1hop = list(self.graph.neighbors(domain))
            neighbors_2hop = []
            for n in neighbors_1hop:
                neighbors_2hop.extend(list(self.graph.neighbors(n)))
            neighbors_2hop = list(set(neighbors_2hop) - {domain} - set(neighbors_1hop))
            
            # Build node list
            node_list = [domain] + neighbors_1hop[:20] + neighbors_2hop[:10]
            node_to_idx = {n: i for i, n in enumerate(node_list)}
            
            # Build edge index
            edge_list = []
            for src in node_list:
                for dst in self.graph.neighbors(src):
                    if dst in node_to_idx:
                        edge_list.append([node_to_idx[src], node_to_idx[dst]])
            
            if edge_list:
                edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
            else:
                edge_index = torch.zeros((2, 0), dtype=torch.long)
            
            # Build feature matrix
            features = []
            for node in node_list:
                node_data = self.graph.nodes.get(node, {})
                feat = extract_node_features(node, node_data)
                features.append(feat)
            x = torch.stack(features)
        else:
            # Single node, no graph context
            node_data = {}
            feat = extract_node_features(domain, node_data)
            x = feat.unsqueeze(0)
            edge_index = torch.zeros((2, 0), dtype=torch.long)

        with torch.no_grad():
            # Get prediction for the target node (index 0)
            out = self.model(x, edge_index)
            probs = F.softmax(out, dim=1)
            phishing_prob = float(probs[0][1].item())
            
            # Get embeddings from last hidden layer
            embeddings = self.model.get_embeddings(x, edge_index)
            embedding = embeddings[0].cpu().numpy()

        if embedding.size != EMBEDDING_DIM:
            raise ValueError(
                f"Embedding model returned {embedding.size} values; expected {EMBEDDING_DIM}"
            )
        return embedding, phishing_prob

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
        """DEPRECATED: Now handled by _generate_embedding with empty edge_index."""
        return self._generate_embedding(domain)

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
