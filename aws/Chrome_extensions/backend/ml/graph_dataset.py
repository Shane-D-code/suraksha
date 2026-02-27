"""
PhishGuard Graph Dataset Preparation
Exports threat intelligence graph data for GNN training
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'threat_intel'))

import csv
import logging
from typing import Dict, List, Tuple
import numpy as np
from datetime import datetime

from database import ThreatDatabase
from graph_engine import InfrastructureGraph

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GraphDatasetExporter:
    """Exports graph data for GNN training"""
    
    def __init__(self, db_path: str = '../threat_intel.db'):
        self.db = ThreatDatabase(db_path)
        self.graph = InfrastructureGraph()
        self.node_id_map = {}
        self.node_counter = 0
        
    def export_dataset(self, output_dir: str = 'data'):
        """Export complete dataset"""
        os.makedirs(output_dir, exist_ok=True)
        
        logger.info("Exporting graph dataset...")
        
        # Load graph from database
        self._load_graph_from_db()
        
        # Export nodes
        nodes_file = os.path.join(output_dir, 'nodes.csv')
        self._export_nodes(nodes_file)
        
        # Export edges
        edges_file = os.path.join(output_dir, 'edges.csv')
        self._export_edges(edges_file)
        
        # Export labels
        labels_file = os.path.join(output_dir, 'labels.csv')
        self._export_labels(labels_file)
        
        # Export features
        features_file = os.path.join(output_dir, 'features.csv')
        self._export_features(features_file)
        
        logger.info(f"Dataset exported to {output_dir}/")
        
        return {
            'nodes': nodes_file,
            'edges': edges_file,
            'labels': labels_file,
            'features': features_file
        }
    
    def _load_graph_from_db(self):
        """Load graph structure from database"""
        logger.info("Loading graph from database...")
        
        # Get all domains
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            # Load domains
            cursor.execute('SELECT * FROM domains WHERE is_active = 1')
            domains = cursor.fetchall()
            
            for domain in domains:
                self.graph.add_domain(
                    domain['domain_name'],
                    risk_score=domain['risk_score'],
                    confidence=domain['confidence'],
                    first_seen=domain['first_seen']
                )
            
            # Load IPs
            cursor.execute('SELECT * FROM ips')
            ips = cursor.fetchall()
            
            for ip in ips:
                self.graph.add_ip(ip['ip_address'])
            
            # Load domain-IP relationships
            cursor.execute('''
                SELECT d.domain_name, i.ip_address
                FROM domain_ip_relations dir
                JOIN domains d ON dir.domain_id = d.domain_id
                JOIN ips i ON dir.ip_id = i.ip_id
            ''')
            relations = cursor.fetchall()
            
            for rel in relations:
                self.graph.link_domain_ip(rel['domain_name'], rel['ip_address'])
        
        logger.info(f"Loaded {len(domains)} domains, {len(ips)} IPs")
    
    def _get_node_id(self, node_name: str) -> int:
        """Get or create node ID"""
        if node_name not in self.node_id_map:
            self.node_id_map[node_name] = self.node_counter
            self.node_counter += 1
        return self.node_id_map[node_name]
    
    def _export_nodes(self, filepath: str):
        """Export nodes with types"""
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['node_id', 'node_name', 'node_type'])
            
            for node in self.graph.graph.nodes():
                node_id = self._get_node_id(node)
                node_type = self.graph.graph.nodes[node].get('node_type', 'unknown')
                writer.writerow([node_id, node, node_type])
        
        logger.info(f"Exported {len(self.node_id_map)} nodes")
    
    def _export_edges(self, filepath: str):
        """Export edges with types"""
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['source_id', 'target_id', 'edge_type'])
            
            edge_count = 0
            for source, target in self.graph.graph.edges():
                source_id = self._get_node_id(source)
                target_id = self._get_node_id(target)
                edge_type = self.graph.graph[source][target].get('edge_type', 'unknown')
                writer.writerow([source_id, target_id, edge_type])
                edge_count += 1
        
        logger.info(f"Exported {edge_count} edges")
    
    def _export_labels(self, filepath: str):
        """Export labels (only for domains)"""
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['node_id', 'label'])
            
            label_count = 0
            for node in self.graph.graph.nodes():
                node_type = self.graph.graph.nodes[node].get('node_type')
                
                if node_type == 'domain':
                    node_id = self._get_node_id(node)
                    risk_score = self.graph.graph.nodes[node].get('risk_score', 0.0)
                    
                    # Label as malicious if risk_score > 0.7
                    label = 1 if risk_score > 0.7 else 0
                    
                    writer.writerow([node_id, label])
                    label_count += 1
        
        logger.info(f"Exported {label_count} labels")
    
    def _export_features(self, filepath: str):
        """Export node features"""
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Feature names
            feature_names = [
                'node_id',
                'domain_length', 'digit_ratio', 'hyphen_count', 'subdomain_count',
                'tld_suspicious', 'risk_score', 'degree', 'clustering_coef'
            ]
            writer.writerow(feature_names)
            
            for node in self.graph.graph.nodes():
                node_id = self._get_node_id(node)
                node_type = self.graph.graph.nodes[node].get('node_type')
                
                if node_type == 'domain':
                    features = self._extract_domain_features(node)
                elif node_type == 'ip':
                    features = self._extract_ip_features(node)
                else:
                    features = self._extract_default_features(node)
                
                writer.writerow([node_id] + features)
        
        logger.info(f"Exported features for {len(self.node_id_map)} nodes")
    
    def _extract_domain_features(self, domain: str) -> List[float]:
        """Extract features for domain node"""
        # Domain length
        domain_length = len(domain)
        
        # Digit ratio
        digit_count = sum(c.isdigit() for c in domain)
        digit_ratio = digit_count / len(domain) if len(domain) > 0 else 0
        
        # Hyphen count
        hyphen_count = domain.count('-')
        
        # Subdomain count
        subdomain_count = len(domain.split('.')) - 2
        
        # TLD suspicious (free TLDs)
        suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top'}
        tld = domain.split('.')[-1] if '.' in domain else ''
        tld_suspicious = 1.0 if tld in suspicious_tlds else 0.0
        
        # Risk score
        risk_score = self.graph.graph.nodes[domain].get('risk_score', 0.0)
        
        # Graph features
        degree = self.graph.graph.degree(domain)
        
        # Clustering coefficient
        try:
            import networkx as nx
            clustering_coef = nx.clustering(self.graph.graph, domain)
        except:
            clustering_coef = 0.0
        
        return [
            domain_length / 100.0,  # Normalize
            digit_ratio,
            hyphen_count / 10.0,  # Normalize
            subdomain_count / 5.0,  # Normalize
            tld_suspicious,
            risk_score,
            degree / 50.0,  # Normalize
            clustering_coef
        ]
    
    def _extract_ip_features(self, ip: str) -> List[float]:
        """Extract features for IP node"""
        # Shared domain count
        degree = self.graph.graph.degree(ip)
        
        # Default features
        return [
            0.0,  # domain_length (N/A)
            0.0,  # digit_ratio (N/A)
            0.0,  # hyphen_count (N/A)
            0.0,  # subdomain_count (N/A)
            0.0,  # tld_suspicious (N/A)
            0.0,  # risk_score (N/A)
            degree / 50.0,  # Normalize
            0.0   # clustering_coef
        ]
    
    def _extract_default_features(self, node: str) -> List[float]:
        """Extract default features for other node types"""
        degree = self.graph.graph.degree(node)
        return [0.0] * 6 + [degree / 50.0, 0.0]


# Example usage
if __name__ == '__main__':
    exporter = GraphDatasetExporter('../threat_intel.db')
    files = exporter.export_dataset('data')
    
    print("\nDataset exported:")
    for key, filepath in files.items():
        print(f"  {key}: {filepath}")
