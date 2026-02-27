"""
PhishGuard Graph Neural Network Model
GraphSAGE-based infrastructure threat detection
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from torch_geometric.nn import SAGEConv, global_mean_pool
from torch_geometric.data import Data
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PhishGuardGNN(nn.Module):
    """GraphSAGE model for phishing infrastructure detection"""
    
    def __init__(self, 
                 input_dim: int = 8,
                 hidden_dim: int = 64,
                 output_dim: int = 32,
                 num_layers: int = 3,
                 dropout: float = 0.3):
        super(PhishGuardGNN, self).__init__()
        
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        self.num_layers = num_layers
        self.dropout = dropout
        
        # GraphSAGE layers
        self.convs = nn.ModuleList()
        self.batch_norms = nn.ModuleList()
        
        # Input layer
        self.convs.append(SAGEConv(input_dim, hidden_dim))
        self.batch_norms.append(nn.BatchNorm1d(hidden_dim))
        
        # Hidden layers
        for _ in range(num_layers - 2):
            self.convs.append(SAGEConv(hidden_dim, hidden_dim))
            self.batch_norms.append(nn.BatchNorm1d(hidden_dim))
        
        # Output layer
        self.convs.append(SAGEConv(hidden_dim, output_dim))
        self.batch_norms.append(nn.BatchNorm1d(output_dim))
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(output_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x, edge_index):
        """
        Forward pass
        
        Args:
            x: Node features [num_nodes, input_dim]
            edge_index: Edge indices [2, num_edges]
        
        Returns:
            predictions: Malicious probability [num_nodes, 1]
            embeddings: Node embeddings [num_nodes, output_dim]
        """
        # Graph convolution layers
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            x = self.batch_norms[i](x)
            
            if i < len(self.convs) - 1:
                x = F.relu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)
        
        # Store embeddings
        embeddings = x
        
        # Classification
        predictions = self.classifier(x)
        
        return predictions, embeddings
    
    def get_embeddings(self, x, edge_index):
        """Get node embeddings without classification"""
        self.eval()
        with torch.no_grad():
            _, embeddings = self.forward(x, edge_index)
        return embeddings


class GNNTrainer:
    """Trainer for PhishGuard GNN"""
    
    def __init__(self, 
                 model: PhishGuardGNN,
                 learning_rate: float = 0.001,
                 weight_decay: float = 5e-4):
        self.model = model
        self.optimizer = torch.optim.Adam(
            model.parameters(),
            lr=learning_rate,
            weight_decay=weight_decay
        )
        self.criterion = nn.BCELoss()
        
        self.train_losses = []
        self.val_losses = []
        self.train_accs = []
        self.val_accs = []
    
    def train_epoch(self, data, train_mask):
        """Train for one epoch"""
        self.model.train()
        self.optimizer.zero_grad()
        
        # Forward pass
        predictions, _ = self.model(data.x, data.edge_index)
        
        # Calculate loss only on training nodes
        loss = self.criterion(
            predictions[train_mask].squeeze(),
            data.y[train_mask].float()
        )
        
        # Backward pass
        loss.backward()
        self.optimizer.step()
        
        # Calculate accuracy
        pred_labels = (predictions[train_mask] > 0.5).float().squeeze()
        accuracy = (pred_labels == data.y[train_mask]).float().mean()
        
        return loss.item(), accuracy.item()
    
    def evaluate(self, data, val_mask):
        """Evaluate on validation set"""
        self.model.eval()
        
        with torch.no_grad():
            predictions, _ = self.model(data.x, data.edge_index)
            
            # Calculate loss
            loss = self.criterion(
                predictions[val_mask].squeeze(),
                data.y[val_mask].float()
            )
            
            # Calculate accuracy
            pred_labels = (predictions[val_mask] > 0.5).float().squeeze()
            accuracy = (pred_labels == data.y[val_mask]).float().mean()
        
        return loss.item(), accuracy.item()
    
    def train(self, data, train_mask, val_mask, epochs: int = 100, patience: int = 10):
        """Train model with early stopping"""
        logger.info(f"Training GNN for {epochs} epochs...")
        
        best_val_loss = float('inf')
        patience_counter = 0
        
        for epoch in range(epochs):
            # Train
            train_loss, train_acc = self.train_epoch(data, train_mask)
            
            # Validate
            val_loss, val_acc = self.evaluate(data, val_mask)
            
            # Store metrics
            self.train_losses.append(train_loss)
            self.val_losses.append(val_loss)
            self.train_accs.append(train_acc)
            self.val_accs.append(val_acc)
            
            # Log progress
            if (epoch + 1) % 10 == 0:
                logger.info(
                    f"Epoch {epoch+1}/{epochs} - "
                    f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f} - "
                    f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}"
                )
            
            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                # Save best model
                self.save_model('models/gnn_best.pt')
            else:
                patience_counter += 1
                
                if patience_counter >= patience:
                    logger.info(f"Early stopping at epoch {epoch+1}")
                    break
        
        logger.info("Training completed!")
        logger.info(f"Best validation loss: {best_val_loss:.4f}")
        
        return {
            'train_losses': self.train_losses,
            'val_losses': self.val_losses,
            'train_accs': self.train_accs,
            'val_accs': self.val_accs,
            'best_val_loss': best_val_loss
        }
    
    def save_model(self, filepath: str):
        """Save model checkpoint"""
        import os
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'train_losses': self.train_losses,
            'val_losses': self.val_losses
        }, filepath)
        
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load model checkpoint"""
        checkpoint = torch.load(filepath)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        
        logger.info(f"Model loaded from {filepath}")


class GNNInference:
    """Inference engine for trained GNN"""
    
    def __init__(self, model_path: str = None):
        self.model = None
        self.model_path = model_path
        self.node_id_map = {}
        self.edge_index = None
        self.node_features = None
        self.num_nodes = 0
        
        if model_path:
            self.load_model(model_path)
    
    def load_model(self, model_path: str):
        """Load trained model"""
        try:
            # Check if model file exists
            import os
            if not os.path.exists(model_path):
                logger.warning(f"Model file not found: {model_path}")
                return False
            
            # Initialize model
            self.model = PhishGuardGNN(
                input_dim=8,
                hidden_dim=64,
                output_dim=32,
                num_layers=3
            )
            
            # Load weights
            checkpoint = torch.load(model_path, map_location='cpu')
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.model.eval()
            
            logger.info(f"GNN model loaded from {model_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load GNN model: {e}")
            self.model = None
            return False
    
    def load_graph_data(self, data_dir: str = 'data'):
        """Load graph data for inference"""
        import os
        import pandas as pd
        
        nodes_file = os.path.join(data_dir, 'nodes.csv')
        edges_file = os.path.join(data_dir, 'edges.csv')
        features_file = os.path.join(data_dir, 'features.csv')
        
        if not all(os.path.exists(f) for f in [nodes_file, edges_file, features_file]):
            logger.warning("Graph data files not found")
            return False
        
        # Load nodes and create ID mapping
        nodes_df = pd.read_csv(nodes_file)
        self.node_id_map = {row['node_name']: row['node_id'] 
                           for _, row in nodes_df.iterrows()}
        self.num_nodes = len(nodes_df)
        
        # Load edges
        edges_df = pd.read_csv(edges_file)
        self.edge_index = torch.tensor([
            edges_df['source_id'].values,
            edges_df['target_id'].values
        ], dtype=torch.long)
        
        # Load features
        features_df = pd.read_csv(features_file)
        feature_cols = [col for col in features_df.columns if col != 'node_id']
        self.node_features = torch.tensor(
            features_df[feature_cols].values, 
            dtype=torch.float
        )
        
        logger.info(f"Graph data loaded: {self.num_nodes} nodes, {self.edge_index.shape[1]} edges")
        return True
    
    def predict(self, x, edge_index):
        """Predict malicious probability for all nodes"""
        if self.model is None:
            return None, None
        
        with torch.no_grad():
            predictions, embeddings = self.model(x, edge_index)
        
        return predictions.numpy(), embeddings.numpy()
    
    def predict_domain(self, domain: str, domain_features: torch.Tensor = None) -> dict:
        """
        Predict risk for a specific domain
        
        Args:
            domain: Domain name to check
            domain_features: Optional pre-computed features
            
        Returns:
            dict with gnn_score, embedding, and cluster_probability
        """
        if self.model is None:
            return {
                'gnn_score': 0.5,
                'embedding': None,
                'cluster_probability': 0.0,
                'error': 'Model not loaded'
            }
        
        # Check if domain is in graph
        if domain in self.node_id_map:
            return self._predict_existing_domain(domain)
        else:
            return self._predict_new_domain(domain, domain_features)
    
    def _predict_existing_domain(self, domain: str) -> dict:
        """Predict for domain already in the graph"""
        node_idx = self.node_id_map[domain]
        
        # Get predictions for all nodes
        predictions, embeddings = self.predict(self.node_features, self.edge_index)
        
        gnn_score = predictions[node_idx][0]
        embedding = embeddings[node_idx]
        
        # Calculate cluster probability (similarity to malicious nodes)
        cluster_prob = self._calculate_cluster_probability(embeddings, node_idx)
        
        return {
            'gnn_score': float(gnn_score),
            'embedding': embedding.tolist(),
            'cluster_probability': float(cluster_prob),
            'domain': domain,
            'in_graph': True
        }
    
    def _predict_new_domain(self, domain: str, domain_features: torch.Tensor = None) -> dict:
        """
        Predict for new (zero-day) domain not in graph
        Uses infrastructure relationships to detect malicious patterns
        """
        if domain_features is None:
            # Extract features from domain string
            domain_features = self._extract_domain_features(domain)
        
        # Find related domains in graph (shared IP, cert, registrar)
        related_domains = self._find_related_domains(domain)
        
        if not related_domains:
            # No infrastructure connections - cannot determine via GNN
            return {
                'gnn_score': 0.3,  # Conservative mid-level
                'embedding': None,
                'cluster_probability': 0.0,
                'domain': domain,
                'in_graph': False,
                'reason': 'No infrastructure connections found'
            }
        
        # Get embeddings of related domains
        predictions, embeddings = self.predict(self.node_features, self.edge_index)
        
        # Aggregate predictions from related domains
        related_scores = []
        for related in related_domains:
            if related in self.node_id_map:
                idx = self.node_id_map[related]
                related_scores.append(predictions[idx][0])
        
        if related_scores:
            # Average malicious score from neighbors
            avg_malicious_score = sum(related_scores) / len(related_scores)
            
            # GNN score based on infrastructure
            gnn_score = min(avg_malicious_score * 0.8 + 0.1, 0.95)
            
            # Cluster probability - how many neighbors are malicious
            malicious_count = sum(1 for s in related_scores if s > 0.5)
            cluster_prob = malicious_count / len(related_scores)
            
            return {
                'gnn_score': float(gnn_score),
                'embedding': None,
                'cluster_probability': float(cluster_prob),
                'domain': domain,
                'in_graph': False,
                'related_domains': related_domains[:5],
                'related_malicious_count': malicious_count,
                'detection_method': 'infrastructure_propagation'
            }
        
        return {
            'gnn_score': 0.3,
            'embedding': None,
            'cluster_probability': 0.0,
            'domain': domain,
            'in_graph': False
        }
    
    def _calculate_cluster_probability(self, embeddings: np.ndarray, node_idx: int) -> float:
        """Calculate probability of domain being in a malicious cluster"""
        # Get embeddings of known malicious domains
        predictions, _ = self.predict(self.node_features, self.edge_index)
        
        # Find highly confident malicious nodes (score > 0.7)
        malicious_indices = np.where(predictions.flatten() > 0.7)[0]
        
        if len(malicious_indices) == 0:
            return 0.0
        
        # Calculate cosine similarity to malicious cluster
        node_embedding = embeddings[node_idx]
        malicious_embeddings = embeddings[malicious_indices]
        
        # Cosine similarity
        from sklearn.metrics.pairwise import cosine_similarity
        similarities = cosine_similarity(
            node_embedding.reshape(1, -1),
            malicious_embeddings
        )[0]
        
        # Return average similarity
        return float(np.mean(similarities))
    
    def _find_related_domains(self, domain: str) -> list:
        """Find domains sharing infrastructure with given domain"""
        # This requires access to the full graph structure
        # For now, return empty list - will be populated by graph_engine
        return []
    
    def _extract_domain_features(self, domain: str) -> torch.Tensor:
        """Extract features for a new domain"""
        # Domain length
        domain_length = len(domain) / 100.0
        
        # Digit ratio
        digit_count = sum(c.isdigit() for c in domain)
        digit_ratio = digit_count / len(domain) if len(domain) > 0 else 0
        
        # Hyphen count
        hyphen_count = domain.count('-') / 10.0
        
        # Subdomain count
        subdomain_count = (len(domain.split('.')) - 2) / 5.0
        
        # TLD suspicious
        suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top'}
        tld = domain.split('.')[-1] if '.' in domain else ''
        tld_suspicious = 1.0 if tld in suspicious_tlds else 0.0
        
        # Risk score (unknown for new domain)
        risk_score = 0.0
        
        # Default graph features
        degree = 0.0
        clustering_coef = 0.0
        
        return torch.tensor([[
            domain_length, digit_ratio, hyphen_count, subdomain_count,
            tld_suspicious, risk_score, degree, clustering_coef
        ]], dtype=torch.float)
    
    def get_embedding(self, domain: str) -> list:
        """Get embedding vector for a domain"""
        if self.model is None:
            return None
        
        result = self.predict_domain(domain)
        return result.get('embedding')
    
    def find_similar_domains(self, domain: str, top_k: int = 5) -> list:
        """Find similar domains using embedding similarity"""
        if self.model is None:
            return []
        
        # Get target embedding
        target_embedding = self.get_embedding(domain)
        if target_embedding is None:
            return []
        
        # Get all predictions and embeddings
        predictions, embeddings = self.predict(self.node_features, self.edge_index)
        
        # Calculate cosine similarity
        from sklearn.metrics.pairwise import cosine_similarity
        similarities = cosine_similarity(
            np.array(target_embedding).reshape(1, -1),
            embeddings
        )[0]
        
        # Get top K similar domains
        # Exclude self
        if domain in self.node_id_map:
            self_idx = self.node_id_map[domain]
            similarities[self_idx] = -1
        
        top_indices = np.argsort(similarities)[::-1][:top_k]
        
        # Get domain names
        id_to_name = {v: k for k, v in self.node_id_map.items()}
        
        results = []
        for idx in top_indices:
            if similarities[idx] > 0:
                results.append({
                    'domain': id_to_name.get(idx, f'unknown_{idx}'),
                    'similarity': float(similarities[idx]),
                    'gnn_score': float(predictions[idx][0])
                })
        
        return results


# Example usage
if __name__ == '__main__':
    # Create model
    model = PhishGuardGNN(
        input_dim=8,
        hidden_dim=64,
        output_dim=32,
        num_layers=3
    )
    
    print("PhishGuard GNN Model:")
    print(f"  Input dim: {model.input_dim}")
    print(f"  Hidden dim: {model.hidden_dim}")
    print(f"  Output dim: {model.output_dim}")
    print(f"  Layers: {model.num_layers}")
    print(f"  Parameters: {sum(p.numel() for p in model.parameters())}")
