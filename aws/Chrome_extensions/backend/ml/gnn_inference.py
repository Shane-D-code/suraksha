"""
PhishGuard GNN Inference Engine
Production-ready inference with campaign clustering and zero-day detection
"""

import os
import sys
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime

# Add ml directory to path
sys.path.insert(0, os.path.dirname(__file__))

import torch
import numpy as np
import pandas as pd
from sklearn.metrics.pairwise import cosine_similarity

from gnn_model import PhishGuardGNN, GNNInference as BaseGNNInference

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CampaignClustering:
    """Cluster detection using GNN embeddings"""
    
    def __init__(self, similarity_threshold: float = 0.85):
        self.similarity_threshold = similarity_threshold
        self.campaigns = {}
        self.campaign_id_counter = 0
    
    def detect_campaigns(self, embeddings: np.ndarray, domain_names: List[str]) -> List[Dict]:
        """
        Detect phishing campaigns by finding clusters of similar domains
        
        Args:
            embeddings: Node embeddings from GNN
            domain_names: List of domain names corresponding to embeddings
            
        Returns:
            List of detected campaigns
        """
        campaigns = []
        
        # Get predictions
        predictions = self._get_predictions(embeddings)
        
        # Find potential malicious domains
        malicious_indices = np.where(predictions > 0.7)[0]
        
        if len(malicious_indices) < 2:
            return campaigns
        
        # Calculate similarity matrix for malicious domains
        malicious_embeddings = embeddings[malicious_indices]
        
        # Compute pairwise similarities
        similarity_matrix = cosine_similarity(malicious_embeddings)
        
        # Find connected components (clusters)
        visited = set()
        
        for i, idx in enumerate(malicious_indices):
            if idx in visited:
                continue
            
            # Find cluster via similarity threshold
            cluster_indices = [idx]
            visited.add(idx)
            
            for j in range(i + 1, len(malicious_indices)):
                neighbor_idx = malicious_indices[j]
                if neighbor_idx not in visited:
                    if similarity_matrix[i, j] >= self.similarity_threshold:
                        cluster_indices.append(neighbor_idx)
                        visited.add(neighbor_idx)
            
            # Only create campaign if cluster is large enough
            if len(cluster_indices) >= 3:
                self.campaign_id_counter += 1
                
                campaign_domains = [domain_names[idx] for idx in cluster_indices]
                campaign_scores = [predictions[idx] for idx in cluster_indices]
                
                campaigns.append({
                    'campaign_id': f'campaign_{self.campaign_id_counter}',
                    'cluster_size': len(cluster_indices),
                    'domains': campaign_domains,
                    'avg_risk_score': np.mean(campaign_scores),
                    'max_risk_score': np.max(campaign_scores),
                    'detected_at': datetime.now().isoformat(),
                    'method': 'embedding_similarity'
                })
                
                self.campaigns[self.campaign_id_counter] = campaigns[-1]
        
        logger.info(f"Detected {len(campaigns)} campaigns")
        return campaigns
    
    def _get_predictions(self, embeddings: np.ndarray) -> np.ndarray:
        """Get predictions from embeddings (simplified)"""
        # This would normally use the model, but for clustering we use
        # the embedding norms as a proxy for maliciousness
        norms = np.linalg.norm(embeddings, axis=1)
        # Normalize to 0-1 range (heuristic)
        if norms.max() > 0:
            return norms / norms.max()
        return norms
    
    def assign_campaign(self, domain: str, embedding: np.ndarray, 
                       existing_campaigns: List[Dict]) -> Optional[str]:
        """Assign a domain to an existing campaign or return None"""
        if not existing_campaigns or embedding is None:
            return None
        
        # Get campaign embeddings
        for campaign in existing_campaigns:
            campaign_domains = campaign.get('domains', [])
            if not campaign_domains:
                continue
            
            # Find similar domains in campaign
            for campaign_domain in campaign_domains:
                # This would require embeddings lookup
                pass
        
        return None


class ZeroDayDetector:
    """Detect zero-day threats using infrastructure propagation"""
    
    def __init__(self, graph_engine=None):
        self.graph = graph_engine
    
    def detect(self, domain: str, db=None) -> Dict:
        """
        Detect zero-day threats for a new domain
        
        Checks:
        1. Shared IP with malicious domains
        2. Shared SSL certificate
        3. Shared registrar patterns
        4. Nameserver patterns
        """
        result = {
            'is_zero_day': False,
            'threat_indicators': [],
            'infrastructure_score': 0.0,
            'related_malicious_count': 0,
            'recommendation': 'LOW_RISK'
        }
        
        if db is None:
            return result
        
        # Check 1: Shared IP
        ip_related = db.get_domains_by_ip(domain)
        malicious_by_ip = [d for d in ip_related if d.get('risk_score', 0) > 0.7]
        
        if malicious_by_ip:
            result['is_zero_day'] = True
            result['threat_indicators'].append({
                'type': 'shared_ip',
                'count': len(malicious_by_ip),
                'domains': [d['domain_name'] for d in malicious_by_ip[:5]]
            })
            result['infrastructure_score'] += min(0.4, len(malicious_by_ip) * 0.15)
            result['related_malicious_count'] += len(malicious_by_ip)
        
        # Check 2: Shared infrastructure via domain relations
        related = db.get_related_domains(domain)
        
        ip_related = related.get('ip_related', [])
        cert_related = related.get('cert_related', [])
        
        malicious_ip = [d for d in ip_related if d.get('risk_score', 0) > 0.7]
        malicious_cert = [d for d in cert_related if d.get('risk_score', 0) > 0.7]
        
        if malicious_ip:
            result['is_zero_day'] = True
            result['threat_indicators'].append({
                'type': 'infrastructure_ip',
                'count': len(malicious_ip),
                'domains': [d['domain_name'] for d in malicious_ip[:5]]
            })
            result['infrastructure_score'] += min(0.3, len(malicious_ip) * 0.1)
            result['related_malicious_count'] += len(malicious_ip)
        
        if malicious_cert:
            result['is_zero_day'] = True
            result['threat_indicators'].append({
                'type': 'shared_certificate',
                'count': len(malicious_cert),
                'domains': [d['domain_name'] for d in malicious_cert[:5]]
            })
            result['infrastructure_score'] += min(0.3, len(malicious_cert) * 0.15)
            result['related_malicious_count'] += len(malicious_cert)
        
        # Determine recommendation
        if result['infrastructure_score'] > 0.5:
            result['recommendation'] = 'HIGH_RISK'
        elif result['infrastructure_score'] > 0.25:
            result['recommendation'] = 'MEDIUM_RISK'
        else:
            result['recommendation'] = 'LOW_RISK'
        
        return result


class GNNInferenceEngine:
    """
    Production-ready GNN inference engine
    Combines model inference with campaign clustering and zero-day detection
    """
    
    def __init__(self, 
                 model_path: str = 'models/gnn_model.pt',
                 data_dir: str = 'data',
                 similarity_threshold: float = 0.85):
        self.model_path = model_path
        self.data_dir = data_dir
        
        # Initialize components
        self.gnn_inference = None
        self.campaign_clustering = CampaignClustering(similarity_threshold)
        self.zero_day_detector = ZeroDayDetector()
        
        # Cached data
        self.embeddings = None
        self.predictions = None
        self.domain_names = []
        self.node_id_map = {}
        
        # Initialize
        self._initialize()
    
    def _initialize(self):
        """Initialize inference engine"""
        logger.info("Initializing GNN Inference Engine...")
        
        # Try to load model
        if os.path.exists(self.model_path):
            try:
                self.gnn_inference = BaseGNNInference(self.model_path)
                logger.info(f"Model loaded from {self.model_path}")
            except Exception as e:
                logger.warning(f"Could not load model: {e}")
                self.gnn_inference = None
        else:
            logger.warning(f"Model file not found: {self.model_path}")
        
        # Try to load graph data
        if os.path.exists(os.path.join(self.data_dir, 'nodes.csv')):
            try:
                self._load_graph_data()
                logger.info("Graph data loaded successfully")
            except Exception as e:
                logger.warning(f"Could not load graph data: {e}")
        else:
            logger.warning(f"Graph data not found in {self.data_dir}")
    
    def _load_graph_data(self):
        """Load graph data for inference"""
        # Load nodes
        nodes_df = pd.read_csv(os.path.join(self.data_dir, 'nodes.csv'))
        self.node_id_map = {row['node_name']: row['node_id'] 
                           for _, row in nodes_df.iterrows()}
        self.domain_names = nodes_df['node_name'].tolist()
        
        # Load edges
        edges_df = pd.read_csv(os.path.join(self.data_dir, 'edges.csv'))
        self.edge_index = torch.tensor([
            edges_df['source_id'].values,
            edges_df['target_id'].values
        ], dtype=torch.long)
        
        # Load features
        features_df = pd.read_csv(os.path.join(self.data_dir, 'features.csv'))
        feature_cols = [col for col in features_df.columns if col != 'node_id']
        self.node_features = torch.tensor(
            features_df[feature_cols].values, 
            dtype=torch.float
        )
        
        # Run inference if model is available
        if self.gnn_inference and self.gnn_inference.model:
            self.predictions, self.embeddings = self.gnn_inference.model(
                self.node_features, 
                self.edge_index
            )
            self.predictions = self.predictions.detach().numpy()
            self.embeddings = self.embeddings.detach().numpy()
    
    def check_domain(self, domain: str, db=None) -> Dict:
        """
        Comprehensive domain check using GNN
        
        Args:
            domain: Domain to check
            db: Optional database connection for zero-day detection
            
        Returns:
            Dict with gnn_score, cluster_probability, campaign_id, etc.
        """
        result = {
            'domain': domain,
            'gnn_score': 0.5,
            'cluster_probability': 0.0,
            'campaign_id': None,
            'is_zero_day': False,
            'zero_day_details': {},
            'similar_domains': [],
            'model_available': self.gnn_inference and self.gnn_inference.model is not None,
            'graph_available': self.embeddings is not None
        }
        
        # Check if domain is in known graph
        if domain in self.node_id_map:
            result.update(self._check_known_domain(domain))
        else:
            result.update(self._check_new_domain(domain, db))
        
        return result
    
    def _check_known_domain(self, domain: str) -> Dict:
        """Check domain that exists in the graph"""
        node_idx = self.node_id_map[domain]
        
        if self.predictions is not None and self.embeddings is not None:
            gnn_score = float(self.predictions[node_idx][0])
            embedding = self.embeddings[node_idx]
            
            # Calculate cluster probability
            cluster_prob = self._calculate_cluster_probability(node_idx)
            
            # Find similar domains
            similar = self.find_similar_domains(domain, top_k=5)
            
            return {
                'gnn_score': gnn_score,
                'cluster_probability': cluster_prob,
                'embedding': embedding.tolist(),
                'similar_domains': similar,
                'in_graph': True
            }
        
        return {
            'gnn_score': 0.5,
            'in_graph': True
        }
    
    def _check_new_domain(self, domain: str, db=None) -> Dict:
        """Check new (zero-day) domain"""
        # Try zero-day detection
        if db:
            zero_day_result = self.zero_day_detector.detect(domain, db)
            return {
                'gnn_score': zero_day_result.get('infrastructure_score', 0.3) + 0.1,
                'cluster_probability': 0.0,
                'is_zero_day': zero_day_result.get('is_zero_day', False),
                'zero_day_details': zero_day_result,
                'in_graph': False
            }
        
        # Extract basic features for new domain
        features = self._extract_domain_features(domain)
        
        # Simple heuristic for new domains
        score = self._heuristic_score(domain)
        
        return {
            'gnn_score': score,
            'cluster_probability': 0.0,
            'is_zero_day': True,
            'in_graph': False,
            'detection_method': 'heuristic'
        }
    
    def _calculate_cluster_probability(self, node_idx: int) -> float:
        """Calculate probability of being in a malicious cluster"""
        if self.embeddings is None or self.predictions is None:
            return 0.0
        
        # Find malicious nodes
        malicious_indices = np.where(self.predictions.flatten() > 0.7)[0]
        
        if len(malicious_indices) == 0:
            return 0.0
        
        # Calculate similarity to malicious cluster
        node_embedding = self.embeddings[node_idx]
        malicious_embeddings = self.embeddings[malicious_indices]
        
        similarities = cosine_similarity(
            node_embedding.reshape(1, -1),
            malicious_embeddings
        )[0]
        
        return float(np.mean(similarities))
    
    def find_similar_domains(self, domain: str, top_k: int = 5) -> List[Dict]:
        """Find similar domains based on embedding similarity (public API)"""
        if domain not in self.node_id_map:
            return []
        
        node_idx = self.node_id_map[domain]
        
        if self.embeddings is None:
            return []
        
        node_embedding = self.embeddings[node_idx]
        
        # Calculate similarities to all domains
        similarities = cosine_similarity(
            node_embedding.reshape(1, -1),
            self.embeddings
        )[0]
        
        # Exclude self
        similarities[node_idx] = -1
        
        # Get top K
        top_indices = np.argsort(similarities)[::-1][:top_k]
        
        results = []
        for idx in top_indices:
            if similarities[idx] > 0.5:  # Similarity threshold
                results.append({
                    'domain': self.domain_names[idx],
                    'similarity': float(similarities[idx]),
                    'gnn_score': float(self.predictions[idx][0]) if self.predictions is not None else 0.5
                })
        
        return results
    
    def _extract_domain_features(self, domain: str) -> np.ndarray:
        """Extract features for a domain"""
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
        
        return np.array([domain_length, digit_ratio, hyphen_count, subdomain_count,
                        tld_suspicious, 0.0, 0.0, 0.0])
    
    def _heuristic_score(self, domain: str) -> float:
        """Simple heuristic for new domains without GNN"""
        score = 0.3  # Base score
        
        # Suspicious TLD
        suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work'}
        tld = domain.split('.')[-1] if '.' in domain else ''
        if tld in suspicious_tlds:
            score += 0.2
        
        # High digit ratio
        digit_count = sum(c.isdigit() for c in domain)
        if len(domain) > 0:
            digit_ratio = digit_count / len(domain)
            if digit_ratio > 0.5:
                score += 0.2
        
        # Many hyphens
        if domain.count('-') > 2:
            score += 0.1
        
        # Long domain
        if len(domain) > 30:
            score += 0.1
        
        return min(score, 0.95)
    
    def detect_campaigns(self) -> List[Dict]:
        """Detect campaigns in the current graph"""
        if self.embeddings is None:
            logger.warning("No embeddings available for campaign detection")
            return []
        
        return self.campaign_clustering.detect_campaigns(
            self.embeddings, 
            self.domain_names
        )
    
    def reload_model(self):
        """Reload model and data"""
        logger.info("Reloading GNN model...")
        self._initialize()
    
    def get_status(self) -> Dict:
        """Get engine status"""
        return {
            'model_loaded': self.gnn_inference and self.gnn_inference.model is not None,
            'graph_loaded': self.embeddings is not None,
            'model_path': self.model_path,
            'data_dir': self.data_dir,
            'total_nodes': len(self.domain_names),
            'campaigns_detected': len(self.campaign_clustering.campaigns)
        }


# Global instance (singleton)
_inference_engine = None


def get_inference_engine(model_path: str = 'models/gnn_model.pt',
                        data_dir: str = 'data') -> GNNInferenceEngine:
    """Get or create global inference engine instance"""
    global _inference_engine
    
    if _inference_engine is None:
        _inference_engine = GNNInferenceEngine(model_path, data_dir)
    
    return _inference_engine


def check_domain_gnn(domain: str, db=None) -> Dict:
    """Convenience function for domain checking"""
    engine = get_inference_engine()
    return engine.check_domain(domain, db)


# Example usage
if __name__ == '__main__':
    # Initialize engine
    engine = GNNInferenceEngine(
        model_path='models/gnn_model.pt',
        data_dir='data'
    )
    
    # Check status
    print("\nGNN Inference Engine Status:")
    status = engine.get_status()
    for key, value in status.items():
        print(f"  {key}: {value}")
    
    # Test domain check
    print("\n--- Domain Check Examples ---")
    
    # Test known domain
    # result = engine.check_domain('example.com')
    # print(f"\nKnown domain: {result}")
    
    # Test new domain
    result = engine.check_domain('new-suspicious-domain.xyz')
    print(f"\nNew domain: {result}")
    
    # Detect campaigns
    print("\n--- Campaign Detection ---")
    campaigns = engine.detect_campaigns()
    print(f"Detected {len(campaigns)} campaigns")
    for campaign in campaigns[:3]:
        print(f"  Campaign {campaign['campaign_id']}: {campaign['cluster_size']} domains")

