"""
campaign_detector.py
Person 3 — Graph & Threat Intelligence
Detects coordinated phishing campaigns by finding clusters of related domains.

Methods used (in order of sophistication):
  1. Shared infrastructure clustering (IP/cert sharing)
  2. Louvain community detection (graph modularity)
  3. Connected components (exact grouping)

Why this matters:
  Single domain → individual threat
  Campaign detection → attacker infrastructure mapping
  You can block the whole campaign, not just one domain.
"""

import asyncio
import networkx as nx
import numpy as np
import logging
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


# ─── Data Structures ─────────────────────────────────────────────────────────

@dataclass
class Campaign:
    campaign_id: str
    domains: list[str]
    shared_ips: list[str]
    shared_certs: list[str]
    first_seen: datetime
    last_seen: datetime
    domain_count: int = 0
    avg_risk_score: float = 0.0
    risk_level: str = "UNKNOWN"
    detection_method: str = "infrastructure"

    def __post_init__(self):
        self.domain_count = len(self.domains)

    def to_dict(self) -> dict:
        return {
            "campaign_id": self.campaign_id,
            "domain_count": self.domain_count,
            "domains": self.domains[:10],  # cap for API response
            "shared_ips": self.shared_ips,
            "shared_certs": self.shared_certs,
            "risk_level": self.risk_level,
            "avg_risk_score": self.avg_risk_score,
            "detection_method": self.detection_method,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat()
        }


@dataclass
class DomainCampaignResult:
    domain: str
    campaign_id: Optional[str]
    campaign_size: int
    cluster_probability: float
    reason: str


# ─── Campaign Detector ───────────────────────────────────────────────────────

class CampaignDetector:
    """
    Identifies coordinated phishing campaigns from the threat graph.

    Core insight:
      Attackers reuse infrastructure. Multiple phishing domains on the same IP,
      or using the same SSL cert = almost certainly the same campaign.
      The graph makes this visible. Humans can't see it at scale. We can.

    Usage:
      detector = CampaignDetector(graph)
      campaigns = await detector.detect_all_campaigns()
      result = await detector.get_domain_campaign("paypal-secure-login.xyz")
    """

    def __init__(self, graph: nx.DiGraph, db_pool=None, redis_client=None):
        self.graph = graph
        self.db = db_pool
        self.redis = redis_client

        # Campaign cache: campaign_id → Campaign
        self._campaigns: dict[str, Campaign] = {}

        # Domain lookup: domain → campaign_id
        self._domain_to_campaign: dict[str, str] = {}

    def update_graph(self, graph: nx.DiGraph):
        """Hot-swap graph when it updates."""
        self.graph = graph

    # ── Main Detection ────────────────────────────────────────────────────────

    async def detect_all_campaigns(self) -> list[Campaign]:
        """
        Full campaign detection pass. Run this:
          - On startup
          - Every 6 hours via Celery
          - After graph has grown significantly

        Returns all detected campaigns.
        """
        loop = asyncio.get_event_loop()
        campaigns = await loop.run_in_executor(None, self._run_detection)

        # Store results
        self._campaigns = {c.campaign_id: c for c in campaigns}
        self._domain_to_campaign = {}
        for campaign in campaigns:
            for domain in campaign.domains:
                self._domain_to_campaign[domain] = campaign.campaign_id

        # Persist to DB
        if self.db:
            await self._persist_campaigns(campaigns)

        logger.info(f"Campaign detection complete: {len(campaigns)} campaigns found")
        return campaigns

    def _run_detection(self) -> list[Campaign]:
        """
        Synchronous detection logic (runs in executor).
        Combines 3 methods and merges results.
        """
        campaigns = []

        # Method 1: Shared infrastructure (most reliable)
        infra_campaigns = self._detect_by_infrastructure()
        campaigns.extend(infra_campaigns)

        # Method 2: Connected components on domain subgraph
        component_campaigns = self._detect_by_components()
        campaigns.extend(component_campaigns)

        # Method 3: Community detection (Louvain if available)
        community_campaigns = self._detect_by_communities()
        campaigns.extend(community_campaigns)

        # Merge overlapping campaigns
        merged = self._merge_overlapping(campaigns)

        return merged

    # ── Detection Methods ─────────────────────────────────────────────────────

    def _detect_by_infrastructure(self) -> list[Campaign]:
        """
        Finds domains that share IPs or SSL certificates.
        This is the strongest signal — attackers rarely buy new infrastructure.

        Algorithm:
          For each IP node: collect all domains pointing to it.
          If 2+ domains share an IP → potential campaign.
          Same for SSL certs.
        """
        campaigns = []
        campaign_num = 1

        # Group by shared IP
        ip_to_domains = defaultdict(list)
        for node, data in self.graph.nodes(data=True):
            if data.get("node_type") == "ip":
                predecessors = list(self.graph.predecessors(node))
                domain_predecessors = [
                    p for p in predecessors
                    if self.graph.nodes.get(p, {}).get("node_type") == "domain"
                ]
                if len(domain_predecessors) >= 2:
                    ip_to_domains[node] = domain_predecessors

        # Group by shared SSL cert
        cert_to_domains = defaultdict(list)
        for node, data in self.graph.nodes(data=True):
            if data.get("node_type") == "certificate":
                predecessors = list(self.graph.predecessors(node))
                domain_predecessors = [
                    p for p in predecessors
                    if self.graph.nodes.get(p, {}).get("node_type") == "domain"
                ]
                if len(domain_predecessors) >= 2:
                    cert_to_domains[node] = domain_predecessors

        # Build campaigns from shared IPs
        for ip_node, domains in ip_to_domains.items():
            ip_addr = ip_node.replace("ip:", "")
            certs = self._find_shared_certs_for_domains(domains, cert_to_domains)

            campaigns.append(Campaign(
                campaign_id=f"infra_{campaign_num:03d}",
                domains=domains,
                shared_ips=[ip_addr],
                shared_certs=certs,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                avg_risk_score=self._avg_risk(domains),
                risk_level=self._risk_level(domains),
                detection_method="shared_infrastructure"
            ))
            campaign_num += 1

        return campaigns

    def _find_shared_certs_for_domains(self, domains: list[str],
                                        cert_to_domains: dict) -> list[str]:
        """Find SSL certs shared by this group of domains."""
        domain_set = set(domains)
        shared_certs = []
        for cert_node, cert_domains in cert_to_domains.items():
            if len(domain_set & set(cert_domains)) >= 2:
                shared_certs.append(cert_node.replace("cert:", ""))
        return shared_certs

    def _detect_by_components(self) -> list[Campaign]:
        """
        Connected components analysis on domain-only subgraph.
        Domains that can reach each other = potentially related.
        """
        # Extract only domain nodes
        domain_nodes = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("node_type") == "domain"
        ]

        # Build undirected subgraph for component analysis
        domain_subgraph = self.graph.subgraph(domain_nodes).to_undirected()
        components = list(nx.connected_components(domain_subgraph))

        campaigns = []
        for i, component in enumerate(components):
            if len(component) < 2:
                continue  # Single domain, not a campaign

            domains = list(component)
            campaigns.append(Campaign(
                campaign_id=f"comp_{i:03d}",
                domains=domains,
                shared_ips=[],
                shared_certs=[],
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                avg_risk_score=self._avg_risk(domains),
                risk_level=self._risk_level(domains),
                detection_method="connected_components"
            ))

        return campaigns

    def _detect_by_communities(self) -> list[Campaign]:
        """
        Louvain community detection — finds densely connected groups.
        More sophisticated than connected components.
        Handles partial connections between campaign domains.

        Falls back gracefully if community library not installed.
        """
        try:
            import community as community_louvain
        except ImportError:
            logger.debug("python-louvain not installed, skipping community detection")
            return []

        undirected = self.graph.to_undirected()
        if undirected.number_of_nodes() < 4:
            return []

        partition = community_louvain.best_partition(undirected)

        # Group nodes by community ID
        communities = defaultdict(list)
        for node, community_id in partition.items():
            if self.graph.nodes.get(node, {}).get("node_type") == "domain":
                communities[community_id].append(node)

        campaigns = []
        for i, (community_id, domains) in enumerate(communities.items()):
            if len(domains) < 2:
                continue

            campaigns.append(Campaign(
                campaign_id=f"comm_{i:03d}",
                domains=domains,
                shared_ips=[],
                shared_certs=[],
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                avg_risk_score=self._avg_risk(domains),
                risk_level=self._risk_level(domains),
                detection_method="louvain_community"
            ))

        return campaigns

    # ── Merging ───────────────────────────────────────────────────────────────

    def _merge_overlapping(self, campaigns: list[Campaign]) -> list[Campaign]:
        """
        Multiple methods may detect the same campaign differently.
        Union-Find merges campaigns that share 2+ domains.
        """
        if not campaigns:
            return []

        # Build domain → campaign index
        domain_to_indices = defaultdict(list)
        for i, campaign in enumerate(campaigns):
            for domain in campaign.domains:
                domain_to_indices[domain].append(i)

        # Union-Find
        parent = list(range(len(campaigns)))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x, y):
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py

        # Merge campaigns that share domains
        for domain, indices in domain_to_indices.items():
            for i in range(1, len(indices)):
                union(indices[0], indices[i])

        # Build merged campaigns
        groups = defaultdict(list)
        for i, campaign in enumerate(campaigns):
            groups[find(i)].append(campaign)

        merged = []
        for group_campaigns in groups.values():
            all_domains = list(set(
                d for c in group_campaigns for d in c.domains
            ))
            all_ips = list(set(
                ip for c in group_campaigns for ip in c.shared_ips
            ))
            all_certs = list(set(
                cert for c in group_campaigns for cert in c.shared_certs
            ))

            # Use the most specific detection method
            methods = [c.detection_method for c in group_campaigns]
            best_method = "shared_infrastructure" if "shared_infrastructure" in methods else methods[0]

            # Stable campaign ID based on sorted domains
            cid_hash = abs(hash(tuple(sorted(all_domains[:5])))) % 10000
            campaign_id = f"campaign_{cid_hash:04d}"

            merged.append(Campaign(
                campaign_id=campaign_id,
                domains=all_domains,
                shared_ips=all_ips,
                shared_certs=all_certs,
                first_seen=min(c.first_seen for c in group_campaigns),
                last_seen=max(c.last_seen for c in group_campaigns),
                avg_risk_score=self._avg_risk(all_domains),
                risk_level=self._risk_level(all_domains),
                detection_method=best_method
            ))

        return sorted(merged, key=lambda c: c.domain_count, reverse=True)

    # ── Domain Lookup ─────────────────────────────────────────────────────────

    async def get_domain_campaign(self, domain: str) -> DomainCampaignResult:
        """
        Look up which campaign a specific domain belongs to.
        Call this from /scan or /investigate endpoints.
        """
        campaign_id = self._domain_to_campaign.get(domain)

        if campaign_id:
            campaign = self._campaigns[campaign_id]
            return DomainCampaignResult(
                domain=domain,
                campaign_id=campaign_id,
                campaign_size=campaign.domain_count,
                cluster_probability=min(campaign.domain_count / 5.0, 1.0),
                reason=f"Part of campaign with {campaign.domain_count} domains "
                       f"sharing {len(campaign.shared_ips)} IP(s)"
            )

        # Check infrastructure in live graph (domain may be new)
        neighbors = self._get_domain_neighbors(domain)
        if neighbors:
            return DomainCampaignResult(
                domain=domain,
                campaign_id=None,
                campaign_size=len(neighbors) + 1,
                cluster_probability=min(len(neighbors) / 3.0, 1.0),
                reason=f"Shares infrastructure with {len(neighbors)} other domain(s)"
            )

        return DomainCampaignResult(
            domain=domain,
            campaign_id=None,
            campaign_size=1,
            cluster_probability=0.0,
            reason="No campaign association found"
        )

    def _get_domain_neighbors(self, domain: str) -> list[str]:
        if domain not in self.graph:
            return []
        neighbors = []
        for intermediate in self.graph.neighbors(domain):
            for co_domain in self.graph.predecessors(intermediate):
                node_type = self.graph.nodes.get(co_domain, {}).get("node_type")
                if co_domain != domain and node_type == "domain":
                    neighbors.append(co_domain)
        return list(set(neighbors))

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _avg_risk(self, domains: list[str]) -> float:
        scores = [
            self.graph.nodes.get(d, {}).get("gnn_score", 0.0)
            for d in domains
        ]
        return round(sum(scores) / max(len(scores), 1), 3)

    def _risk_level(self, domains: list[str]) -> str:
        avg = self._avg_risk(domains)
        if avg >= 0.7:
            return "HIGH"
        elif avg >= 0.4:
            return "MEDIUM"
        return "LOW"

    # ── Persistence ───────────────────────────────────────────────────────────

    async def _persist_campaigns(self, campaigns: list[Campaign]):
        for campaign in campaigns:
            await self.db.execute("""
                INSERT INTO campaigns (campaign_id, domain_count, domains, shared_ips,
                                       shared_certs, risk_level, avg_risk_score,
                                       detection_method, first_seen, last_seen)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (campaign_id) DO UPDATE SET
                    domain_count = EXCLUDED.domain_count,
                    domains = EXCLUDED.domains,
                    risk_level = EXCLUDED.risk_level,
                    avg_risk_score = EXCLUDED.avg_risk_score,
                    last_seen = EXCLUDED.last_seen
            """,
                campaign.campaign_id,
                campaign.domain_count,
                json.dumps(campaign.domains),
                json.dumps(campaign.shared_ips),
                json.dumps(campaign.shared_certs),
                campaign.risk_level,
                campaign.avg_risk_score,
                campaign.detection_method,
                campaign.first_seen,
                campaign.last_seen
            )

    def get_stats(self) -> dict:
        return {
            "total_campaigns": len(self._campaigns),
            "total_domains_in_campaigns": sum(c.domain_count for c in self._campaigns.values()),
            "high_risk_campaigns": sum(1 for c in self._campaigns.values() if c.risk_level == "HIGH"),
        }
