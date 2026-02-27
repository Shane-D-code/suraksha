"""
PhishGuard Infrastructure Graph Engine
Builds and analyzes relationships between domains, IPs, and certificates
Detects coordinated phishing campaigns through graph analysis
"""

import networkx as nx
import logging
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class InfrastructureGraph:
    """Graph-based infrastructure relationship analyzer"""
    
    def __init__(self):
        self.graph = nx.Graph()
        self.domain_clusters = []
        self.campaign_id_counter = 0
        
    def add_domain(self, domain: str, risk_score: float = 0.0, **attributes):
        """Add domain node to graph"""
        self.graph.add_node(
            domain,
            node_type='domain',
            risk_score=risk_score,
            **attributes
        )
    
    def add_ip(self, ip: str, **attributes):
        """Add IP node to graph"""
        self.graph.add_node(
            ip,
            node_type='ip',
            **attributes
        )
    
    def add_certificate(self, cert_fingerprint: str, **attributes):
        """Add certificate node to graph"""
        self.graph.add_node(
            cert_fingerprint,
            node_type='certificate',
            **attributes
        )
    
    def link_domain_ip(self, domain: str, ip: str, weight: float = 1.0):
        """Create edge between domain and IP"""
        self.graph.add_edge(domain, ip, edge_type='hosts_on', weight=weight)
    
    def link_domain_cert(self, domain: str, cert: str, weight: float = 1.0):
        """Create edge between domain and certificate"""
        self.graph.add_edge(domain, cert, edge_type='uses_cert', weight=weight)
    
    def link_domain_registrar(self, domain: str, registrar: str, weight: float = 1.0):
        """Create edge between domain and registrar"""
        if not self.graph.has_node(registrar):
            self.graph.add_node(registrar, node_type='registrar')
        self.graph.add_edge(domain, registrar, edge_type='registered_with', weight=weight)
    
    def get_domain_neighbors(self, domain: str) -> Dict[str, List[str]]:
        """Get all neighbors of a domain grouped by type"""
        if domain not in self.graph:
            return {}
        
        neighbors = defaultdict(list)
        for neighbor in self.graph.neighbors(domain):
            node_type = self.graph.nodes[neighbor].get('node_type', 'unknown')
            neighbors[node_type].append(neighbor)
        
        return dict(neighbors)
    
    def find_domains_sharing_ip(self, domain: str) -> List[str]:
        """Find all domains sharing IP with given domain"""
        if domain not in self.graph:
            return []
        
        shared_domains = set()
        
        # Get IPs connected to this domain
        for neighbor in self.graph.neighbors(domain):
            if self.graph.nodes[neighbor].get('node_type') == 'ip':
                # Get all domains connected to this IP
                for ip_neighbor in self.graph.neighbors(neighbor):
                    if (self.graph.nodes[ip_neighbor].get('node_type') == 'domain' 
                        and ip_neighbor != domain):
                        shared_domains.add(ip_neighbor)
        
        return list(shared_domains)
    
    def find_domains_sharing_cert(self, domain: str) -> List[str]:
        """Find all domains sharing certificate with given domain"""
        if domain not in self.graph:
            return []
        
        shared_domains = set()
        
        # Get certificates connected to this domain
        for neighbor in self.graph.neighbors(domain):
            if self.graph.nodes[neighbor].get('node_type') == 'certificate':
                # Get all domains connected to this certificate
                for cert_neighbor in self.graph.neighbors(neighbor):
                    if (self.graph.nodes[cert_neighbor].get('node_type') == 'domain' 
                        and cert_neighbor != domain):
                        shared_domains.add(cert_neighbor)
        
        return list(shared_domains)
    
    def calculate_infrastructure_risk(self, domain: str) -> Dict:
        """Calculate infrastructure-based risk score"""
        if domain not in self.graph:
            return {
                'infrastructure_score': 0.0,
                'cluster_size': 0,
                'related_malicious_domains': [],
                'risk_factors': []
            }
        
        risk_factors = []
        malicious_related = []
        
        # Find domains sharing infrastructure
        ip_shared = self.find_domains_sharing_ip(domain)
        cert_shared = self.find_domains_sharing_cert(domain)
        
        # Count malicious neighbors
        malicious_ip_neighbors = 0
        for shared_domain in ip_shared:
            risk_score = self.graph.nodes[shared_domain].get('risk_score', 0.0)
            if risk_score > 0.7:
                malicious_ip_neighbors += 1
                malicious_related.append({
                    'domain': shared_domain,
                    'risk_score': risk_score,
                    'relation': 'shared_ip'
                })
        
        malicious_cert_neighbors = 0
        for shared_domain in cert_shared:
            risk_score = self.graph.nodes[shared_domain].get('risk_score', 0.0)
            if risk_score > 0.7:
                malicious_cert_neighbors += 1
                malicious_related.append({
                    'domain': shared_domain,
                    'risk_score': risk_score,
                    'relation': 'shared_cert'
                })
        
        # Calculate infrastructure score
        infra_score = 0.0
        
        if malicious_ip_neighbors > 0:
            infra_score += min(0.4, malicious_ip_neighbors * 0.15)
            risk_factors.append(f"Shares IP with {malicious_ip_neighbors} malicious domain(s)")
        
        if malicious_cert_neighbors > 0:
            infra_score += min(0.3, malicious_cert_neighbors * 0.15)
            risk_factors.append(f"Shares certificate with {malicious_cert_neighbors} malicious domain(s)")
        
        # Check for large clusters (potential campaign)
        cluster_size = len(ip_shared) + len(cert_shared)
        if cluster_size > 10:
            infra_score += 0.2
            risk_factors.append(f"Part of large infrastructure cluster ({cluster_size} domains)")
        
        # Check for suspicious registrar patterns
        neighbors = self.get_domain_neighbors(domain)
        if 'registrar' in neighbors:
            registrar_domains = self._get_domains_by_registrar(neighbors['registrar'][0])
            if len(registrar_domains) > 50:
                infra_score += 0.1
                risk_factors.append(f"Registrar associated with {len(registrar_domains)} domains")
        
        return {
            'infrastructure_score': min(infra_score, 1.0),
            'cluster_size': cluster_size,
            'related_malicious_domains': malicious_related[:10],  # Limit to 10
            'risk_factors': risk_factors,
            'ip_shared_count': len(ip_shared),
            'cert_shared_count': len(cert_shared)
        }
    
    def _get_domains_by_registrar(self, registrar: str) -> List[str]:
        """Get all domains registered with a registrar"""
        if registrar not in self.graph:
            return []
        
        domains = []
        for neighbor in self.graph.neighbors(registrar):
            if self.graph.nodes[neighbor].get('node_type') == 'domain':
                domains.append(neighbor)
        
        return domains
    
    def detect_campaigns(self, min_cluster_size: int = 5) -> List[Dict]:
        """Detect coordinated phishing campaigns through clustering"""
        campaigns = []
        
        # Find connected components (clusters)
        domain_subgraph = self.graph.subgraph([
            n for n in self.graph.nodes() 
            if self.graph.nodes[n].get('node_type') == 'domain'
        ])
        
        # For each domain, find its infrastructure cluster
        processed = set()
        
        for domain in domain_subgraph.nodes():
            if domain in processed:
                continue
            
            # Get all domains in this infrastructure cluster
            cluster = self._get_infrastructure_cluster(domain)
            
            if len(cluster) >= min_cluster_size:
                # Calculate cluster risk
                cluster_risks = [
                    self.graph.nodes[d].get('risk_score', 0.0) 
                    for d in cluster
                ]
                avg_risk = sum(cluster_risks) / len(cluster_risks) if cluster_risks else 0.0
                
                # Check if cluster is malicious
                malicious_count = sum(1 for r in cluster_risks if r > 0.7)
                
                if malicious_count >= min_cluster_size * 0.5:  # At least 50% malicious
                    self.campaign_id_counter += 1
                    campaigns.append({
                        'campaign_id': self.campaign_id_counter,
                        'cluster_size': len(cluster),
                        'domains': list(cluster),
                        'avg_risk_score': avg_risk,
                        'malicious_count': malicious_count,
                        'detected_at': datetime.now()
                    })
                    
                    processed.update(cluster)
        
        logger.info(f"Detected {len(campaigns)} potential campaigns")
        return campaigns
    
    def _get_infrastructure_cluster(self, domain: str) -> Set[str]:
        """Get all domains in the same infrastructure cluster"""
        cluster = {domain}
        to_process = {domain}
        processed = set()
        
        while to_process:
            current = to_process.pop()
            if current in processed:
                continue
            
            processed.add(current)
            
            # Get domains sharing infrastructure
            ip_shared = self.find_domains_sharing_ip(current)
            cert_shared = self.find_domains_sharing_cert(current)
            
            for related in ip_shared + cert_shared:
                if related not in processed:
                    cluster.add(related)
                    to_process.add(related)
        
        return cluster
    
    def get_graph_statistics(self) -> Dict:
        """Get graph statistics"""
        domain_nodes = [n for n in self.graph.nodes() 
                       if self.graph.nodes[n].get('node_type') == 'domain']
        ip_nodes = [n for n in self.graph.nodes() 
                   if self.graph.nodes[n].get('node_type') == 'ip']
        cert_nodes = [n for n in self.graph.nodes() 
                     if self.graph.nodes[n].get('node_type') == 'certificate']
        
        return {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'domain_nodes': len(domain_nodes),
            'ip_nodes': len(ip_nodes),
            'certificate_nodes': len(cert_nodes),
            'avg_degree': sum(dict(self.graph.degree()).values()) / self.graph.number_of_nodes() if self.graph.number_of_nodes() > 0 else 0
        }
    
    def export_graph(self, filepath: str):
        """Export graph to file"""
        nx.write_gexf(self.graph, filepath)
        logger.info(f"Graph exported to {filepath}")
    
    def import_graph(self, filepath: str):
        """Import graph from file"""
        self.graph = nx.read_gexf(filepath)
        logger.info(f"Graph imported from {filepath}")


# Example usage
if __name__ == '__main__':
    graph = InfrastructureGraph()
    
    # Add test data
    graph.add_domain('malicious1.com', risk_score=0.9)
    graph.add_domain('malicious2.com', risk_score=0.85)
    graph.add_domain('legitimate.com', risk_score=0.1)
    
    graph.add_ip('192.168.1.1')
    graph.add_ip('192.168.1.2')
    
    # Link domains to IPs
    graph.link_domain_ip('malicious1.com', '192.168.1.1')
    graph.link_domain_ip('malicious2.com', '192.168.1.1')  # Shared IP
    graph.link_domain_ip('legitimate.com', '192.168.1.2')
    
    # Calculate infrastructure risk
    risk = graph.calculate_infrastructure_risk('malicious2.com')
    print("\nInfrastructure Risk Analysis:")
    print(f"  Score: {risk['infrastructure_score']}")
    print(f"  Cluster Size: {risk['cluster_size']}")
    print(f"  Risk Factors: {risk['risk_factors']}")
    
    # Detect campaigns
    campaigns = graph.detect_campaigns(min_cluster_size=2)
    print(f"\nDetected Campaigns: {len(campaigns)}")
    for campaign in campaigns:
        print(f"  Campaign {campaign['campaign_id']}: {campaign['cluster_size']} domains")
    
    # Statistics
    stats = graph.get_graph_statistics()
    print("\nGraph Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
