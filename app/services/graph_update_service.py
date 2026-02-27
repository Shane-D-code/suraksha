"""
graph_update_service.py
Person 3 — Graph & Threat Intelligence
Dynamically updates the threat graph after every scan.
No more static CSV loading. Graph grows with real data.
"""

import asyncio
import asyncpg
import networkx as nx
import socket
import ssl
import hashlib
import json
import logging
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ─── Data Structures ────────────────────────────────────────────────────────

@dataclass
class DomainNode:
    domain: str
    ip: Optional[str] = None
    ssl_fingerprint: Optional[str] = None
    registrar: Optional[str] = None
    asn: Optional[str] = None
    gnn_score: float = 0.0
    risk_label: Optional[str] = None
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)


# ─── Graph Update Service ────────────────────────────────────────────────────

class GraphUpdateService:
    """
    Manages the in-memory threat graph and keeps it in sync with PostgreSQL.

    Every time a domain is scanned:
      1. Resolve its IP
      2. Grab its SSL fingerprint
      3. Insert node + edges into the graph
      4. Persist to DB
      5. Invalidate Redis cache so next query gets fresh data

    This replaces the old CSV-loaded static graph.
    """

    def __init__(self, db_pool: asyncpg.Pool, redis_client=None):
        self.db = db_pool
        self.redis = redis_client
        self.graph = nx.DiGraph()
        self._lock = asyncio.Lock()

    # ── Startup ──────────────────────────────────────────────────────────────

    async def load_graph_from_db(self):
        """
        On startup: rebuild in-memory graph from PostgreSQL.
        This replaces loading from nodes.csv / edges.csv.
        """
        async with self._lock:
            self.graph.clear()

            # Load domain nodes
            rows = await self.db.fetch(
                "SELECT domain, node_type, ip, ssl_fingerprint, registrar, asn, gnn_score, risk_label "
                "FROM graph_nodes"
            )
            for row in rows:
                self.graph.add_node(row["domain"], **dict(row))

            # Load IP nodes
            ip_rows = await self.db.fetch("SELECT DISTINCT ip FROM graph_nodes WHERE ip IS NOT NULL")
            for row in ip_rows:
                self.graph.add_node(f"ip:{row['ip']}", node_type="ip")

            # Load certificate nodes
            cert_rows = await self.db.fetch("SELECT DISTINCT ssl_fingerprint FROM graph_nodes WHERE ssl_fingerprint IS NOT NULL")
            for row in cert_rows:
                fp = row["ssl_fingerprint"]
                if fp:
                    self.graph.add_node(f"cert:{fp[:16]}", node_type="certificate")

            # Load edges
            edge_rows = await self.db.fetch(
                "SELECT source, target, relation_type FROM graph_edges"
            )
            for row in edge_rows:
                self.graph.add_edge(row["source"], row["target"], relation=row["relation_type"])

        logger.info(f"Graph loaded from DB: {self.graph.number_of_nodes()} nodes, "
                    f"{self.graph.number_of_edges()} edges")

    # ── Main Entry Point ──────────────────────────────────────────────────────

    async def update_after_scan(self, domain: str, risk_label: str = "UNKNOWN",
                                gnn_score: float = 0.0) -> DomainNode:
        """
        Call this after every /scan.
        Resolves domain info, updates graph + DB in one shot.

        Returns the DomainNode so calling code can use the resolved signals.
        """
        node = DomainNode(domain=domain, risk_label=risk_label, gnn_score=gnn_score)

        # Run resolution concurrently — no point waiting sequentially
        ip, ssl_fp = await asyncio.gather(
            self._resolve_ip(domain),
            self._get_ssl_fingerprint(domain),
            return_exceptions=True
        )

        if isinstance(ip, str):
            node.ip = ip
        if isinstance(ssl_fp, str):
            node.ssl_fingerprint = ssl_fp

        async with self._lock:
            await self._upsert_node(node)
            await self._upsert_edges(node)
            self._update_in_memory(node)

        # Bust the Redis graph cache so GNN picks up new data
        if self.redis:
            await self.redis.delete("graph:data")
            await self.redis.delete(f"embedding:{domain}")

        logger.info(f"Graph updated: {domain} (ip={node.ip}, ssl={node.ssl_fingerprint})")
        return node

    # ── Resolution Helpers ────────────────────────────────────────────────────

    async def _resolve_ip(self, domain: str) -> Optional[str]:
        """DNS resolution. Non-blocking via executor."""
        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, domain),
                timeout=5.0
            )
            return result
        except Exception as e:
            logger.warning(f"IP resolution failed for {domain}: {e}")
            return None

    async def _get_ssl_fingerprint(self, domain: str) -> Optional[str]:
        """
        Grabs SSL cert and hashes it to a fingerprint.
        Same fingerprint across domains = shared infrastructure = strong risk signal.
        """
        try:
            loop = asyncio.get_event_loop()

            def _fetch_cert():
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(
                    socket.create_connection((domain, 443), timeout=5),
                    server_hostname=domain
                ) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    return hashlib.sha256(cert_der).hexdigest()

            return await asyncio.wait_for(
                loop.run_in_executor(None, _fetch_cert),
                timeout=8.0
            )
        except Exception as e:
            logger.debug(f"SSL fingerprint failed for {domain}: {e}")
            return None

    # ── In-Memory Graph Update ────────────────────────────────────────────────

    def _update_in_memory(self, node: DomainNode):
        """Updates NetworkX graph without hitting DB."""
        self.graph.add_node(
            node.domain,
            node_type="domain",
            ip=node.ip,
            ssl_fingerprint=node.ssl_fingerprint,
            gnn_score=node.gnn_score,
            risk_label=node.risk_label,
            last_seen=node.last_seen.isoformat()
        )

        if node.ip:
            ip_key = f"ip:{node.ip}"
            self.graph.add_node(ip_key, node_type="ip")
            self.graph.add_edge(node.domain, ip_key, relation="resolves_to")

        if node.ssl_fingerprint:
            cert_key = f"cert:{node.ssl_fingerprint[:16]}"
            self.graph.add_node(cert_key, node_type="certificate")
            self.graph.add_edge(node.domain, cert_key, relation="uses_cert")

    # ── DB Persistence ───────────────────────────────────────────────────────

    async def _upsert_node(self, node: DomainNode):
        await self.db.execute("""
            INSERT INTO graph_nodes (domain, ip, ssl_fingerprint, registrar, asn, gnn_score, risk_label, last_seen)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (domain) DO UPDATE SET
                ip = EXCLUDED.ip,
                ssl_fingerprint = EXCLUDED.ssl_fingerprint,
                gnn_score = EXCLUDED.gnn_score,
                risk_label = EXCLUDED.risk_label,
                last_seen = EXCLUDED.last_seen
        """, node.domain, node.ip, node.ssl_fingerprint,
             node.registrar, node.asn, node.gnn_score,
             node.risk_label, node.last_seen)

    async def _upsert_edges(self, node: DomainNode):
        if node.ip:
            await self.db.execute("""
                INSERT INTO graph_edges (source, target, relation_type)
                VALUES ($1, $2, 'resolves_to')
                ON CONFLICT (source, target, relation_type) DO NOTHING
            """, node.domain, f"ip:{node.ip}")

        if node.ssl_fingerprint:
            await self.db.execute("""
                INSERT INTO graph_edges (source, target, relation_type)
                VALUES ($1, $2, 'uses_cert')
                ON CONFLICT (source, target, relation_type) DO NOTHING
            """, node.domain, f"cert:{node.ssl_fingerprint[:16]}")

    # ── Utility ─────────────────────────────────────────────────────────────

    def get_neighbors(self, domain: str) -> list[str]:
        """Returns domains that share IP or SSL cert with this domain."""
        if domain not in self.graph:
            return []
        neighbors = []
        for neighbor in self.graph.neighbors(domain):
            # Get domains that point to the same IP or cert
            for co_domain in self.graph.predecessors(neighbor):
                if co_domain != domain:
                    neighbors.append(co_domain)
        return list(set(neighbors))

    def graph_stats(self) -> dict:
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "domain_nodes": sum(1 for _, d in self.graph.nodes(data=True)
                                if d.get("node_type") == "domain"),
            "ip_nodes": sum(1 for _, d in self.graph.nodes(data=True)
                            if d.get("node_type") == "ip"),
        }
