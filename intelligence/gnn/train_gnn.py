"""
train_gnn.py

Train a REAL GraphSAGE model on the threat intelligence graph.
Uses PyTorch Geometric for graph neural network training.
"""

import torch
import torch.nn.functional as F
import networkx as nx
import numpy as np
import asyncio
from pathlib import Path
from typing import Dict, List, Tuple

from torch_geometric.data import Data
from torch_geometric.nn import SAGEConv
from torch_geometric.utils import from_networkx

# Add project root to path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.services.graph import GraphService


# ---------------- PATHS ---------------- #

BASE_PATH = Path(__file__).resolve().parents[2]
MODEL_DIR = BASE_PATH / "ml" / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = MODEL_DIR / "gnn_model.pt"


# ---------------- GRAPHSAGE MODEL ---------------- #

class GraphSAGE(torch.nn.Module):
    """
    2-layer GraphSAGE for node classification.
    Architecture: Input -> SAGEConv -> ReLU -> SAGEConv -> ReLU -> Linear -> Output
    """
    def __init__(self, in_channels: int, hidden_channels: int, out_channels: int = 2):
        super().__init__()
        self.conv1 = SAGEConv(in_channels, hidden_channels)
        self.conv2 = SAGEConv(hidden_channels, hidden_channels)
        self.linear = torch.nn.Linear(hidden_channels, out_channels)

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


# ---------------- FEATURE EXTRACTION ---------------- #

def create_node_features(G: nx.DiGraph) -> torch.Tensor:
    """
    Create meaningful node features for each domain.
    Features:
    1. Domain length
    2. Number of dots (subdomain depth)
    3. Hyphen count
    4. Digit count
    5. PageRank centrality
    6. Malicious neighbor ratio
    7. SSL presence (1/0)
    """
    features = []
    
    # Calculate PageRank for all nodes
    pagerank = nx.pagerank(G, alpha=0.85)
    
    for node in G.nodes():
        node_data = G.nodes[node]
        
        # Basic domain features
        domain_length = len(node)
        dot_count = node.count(".")
        hyphen_count = node.count("-")
        digit_count = sum(c.isdigit() for c in node)
        
        # Graph features
        pr_score = pagerank.get(node, 0.0)
        
        # Count malicious neighbors
        malicious_neighbors = 0
        total_neighbors = 0
        for neighbor in G.neighbors(node):
            total_neighbors += 1
            if G.nodes[neighbor].get("is_malicious", False) or \
               G.nodes[neighbor].get("threat_type") == "phishing":
                malicious_neighbors += 1
        
        malicious_ratio = malicious_neighbors / max(total_neighbors, 1)
        
        # SSL presence
        has_ssl = int(node_data.get("has_ssl", 0))
        
        feat = [
            domain_length / 100.0,  # Normalize
            dot_count / 5.0,  # Normalize
            hyphen_count / 10.0,  # Normalize
            digit_count / 20.0,  # Normalize
            pr_score,
            malicious_ratio,
            has_ssl
        ]
        
        features.append(feat)
    
    return torch.tensor(features, dtype=torch.float)


def create_labels(G: nx.DiGraph) -> torch.Tensor:
    """
    Create labels for nodes.
    1 = Known phishing/malicious domain
    0 = Safe/unknown domain
    """
    labels = []
    
    for node in G.nodes():
        node_data = G.nodes[node]
        
        # Check if node is marked as malicious
        is_malicious = (
            node_data.get("is_malicious", False) or
            node_data.get("threat_type") == "phishing" or
            node_data.get("risk_score", 0) > 0.7
        )
        
        labels.append(1 if is_malicious else 0)
    
    return torch.tensor(labels, dtype=torch.long)


# ---------------- TRAINING ---------------- #

async def load_graph() -> nx.DiGraph:
    """Load the threat intelligence graph."""
    print("Loading graph from GraphService...")
    graph_service = GraphService()
    await graph_service._ensure_graph_loaded()
    print(f"Graph loaded: {graph_service.graph.number_of_nodes()} nodes, {graph_service.graph.number_of_edges()} edges")
    return graph_service.graph


def convert_to_pyg(G: nx.DiGraph) -> Data:
    """Convert NetworkX graph to PyTorch Geometric Data object."""
    print("Converting NetworkX graph to PyTorch Geometric format...")
    
    # Get node list to maintain consistent ordering
    node_list = list(G.nodes())
    node_to_idx = {node: i for i, node in enumerate(node_list)}
    num_nodes = len(node_list)
    
    print(f"Processing {num_nodes} nodes...")
    
    # Create edge index manually
    edge_list = []
    for src, dst in G.edges():
        edge_list.append([node_to_idx[src], node_to_idx[dst]])
    
    if edge_list:
        edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)
    
    # Create node features
    print("Creating node features...")
    features = []
    pagerank = nx.pagerank(G, alpha=0.85)
    
    for node in node_list:
        node_data = G.nodes[node]
        
        # Basic domain features
        domain_length = len(node)
        dot_count = node.count(".")
        hyphen_count = node.count("-")
        digit_count = sum(c.isdigit() for c in node)
        
        # Graph features
        pr_score = pagerank.get(node, 0.0)
        
        # Count malicious neighbors
        malicious_neighbors = 0
        total_neighbors = 0
        for neighbor in G.neighbors(node):
            total_neighbors += 1
            if G.nodes[neighbor].get("is_malicious", False) or \
               G.nodes[neighbor].get("threat_type") == "phishing":
                malicious_neighbors += 1
        
        malicious_ratio = malicious_neighbors / max(total_neighbors, 1)
        
        # SSL presence
        has_ssl = int(node_data.get("has_ssl", 0))
        
        feat = [
            domain_length / 100.0,
            dot_count / 5.0,
            hyphen_count / 10.0,
            digit_count / 20.0,
            pr_score,
            malicious_ratio,
            has_ssl
        ]
        
        features.append(feat)
    
    x = torch.tensor(features, dtype=torch.float)
    
    # Create labels
    print("Creating labels...")
    labels = []
    for node in node_list:
        node_data = G.nodes[node]
        is_malicious = (
            node_data.get("is_malicious", False) or
            node_data.get("threat_type") == "phishing" or
            node_data.get("risk_score", 0) > 0.7
        )
        labels.append(1 if is_malicious else 0)
    
    y = torch.tensor(labels, dtype=torch.long)
    
    # Create PyG Data object
    data = Data(x=x, edge_index=edge_index, y=y)
    data.node_list = node_list  # Store for reference
    
    print(f"Data: {data.num_nodes} nodes, {data.num_edges} edges")
    print(f"Feature dim: {data.x.shape[1]}, Classes: {data.y.max().item() + 1}")
    
    return data


def train_model(data: Data, hidden_channels: int = 64, epochs: int = 100) -> GraphSAGE:
    """Train the GraphSAGE model."""
    print(f"\nTraining GraphSAGE model...")
    print(f"Hidden channels: {hidden_channels}, Epochs: {epochs}")
    
    device = torch.device("cpu")  # Use CPU for compatibility
    data = data.to(device)
    
    # Initialize model
    model = GraphSAGE(
        in_channels=data.x.shape[1],
        hidden_channels=hidden_channels,
        out_channels=2  # Binary classification
    ).to(device)
    
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
    
    # Training loop
    model.train()
    for epoch in range(epochs):
        optimizer.zero_grad()
        
        # Forward pass
        out = model(data.x, data.edge_index)
        
        # Calculate loss
        loss = F.cross_entropy(out, data.y)
        
        # Backward pass
        loss.backward()
        optimizer.step()
        
        # Calculate accuracy
        pred = out.argmax(dim=1)
        correct = (pred == data.y).sum().item()
        acc = correct / data.num_nodes
        
        if (epoch + 1) % 10 == 0 or epoch == 0:
            print(f"Epoch {epoch + 1:3d}, Loss: {loss.item():.4f}, Accuracy: {acc:.4f}")
    
    return model


def evaluate_model(model: GraphSAGE, data: Data) -> Dict[str, float]:
    """Evaluate the trained model."""
    print("\nEvaluating model...")
    
    model.eval()
    with torch.no_grad():
        out = model(data.x, data.edge_index)
        pred = out.argmax(dim=1)
        
        # Overall accuracy
        correct = (pred == data.y).sum().item()
        accuracy = correct / data.num_nodes
        
        # Class-wise metrics
        phishing_mask = data.y == 1
        safe_mask = data.y == 0
        
        phishing_correct = (pred[phishing_mask] == data.y[phishing_mask]).sum().item()
        safe_correct = (pred[safe_mask] == data.y[safe_mask]).sum().item()
        
        phishing_total = phishing_mask.sum().item()
        safe_total = safe_mask.sum().item()
        
        phishing_acc = phishing_correct / max(phishing_total, 1)
        safe_acc = safe_correct / max(safe_total, 1)
        
        print(f"Overall Accuracy: {accuracy:.4f}")
        print(f"Phishing Detection: {phishing_correct}/{phishing_total} ({phishing_acc:.4f})")
        print(f"Safe Detection: {safe_correct}/{safe_total} ({safe_acc:.4f})")
        
        return {
            "accuracy": accuracy,
            "phishing_accuracy": phishing_acc,
            "safe_accuracy": safe_acc
        }


def save_model(model: GraphSAGE, path: Path):
    """Save the trained model."""
    print(f"\nSaving model to {path}...")
    torch.save(model.state_dict(), path)
    print(f"✅ Model saved successfully!")


# ---------------- MAIN ---------------- #

async def main():
    """Main training pipeline."""
    print("=" * 60)
    print("GraphSAGE GNN Training for PhishGuard")
    print("=" * 60)
    
    # Step 1: Load graph
    G = await load_graph()
    
    # Step 2: Convert to PyG format
    data = convert_to_pyg(G)
    
    # Step 3: Train model
    model = train_model(data, hidden_channels=64, epochs=100)
    
    # Step 4: Evaluate
    metrics = evaluate_model(model, data)
    
    # Step 5: Save
    save_model(model, MODEL_PATH)
    
    print("\n" + "=" * 60)
    print("Training Complete!")
    print(f"Model saved to: {MODEL_PATH}")
    print(f"Final Accuracy: {metrics['accuracy']:.4f}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
