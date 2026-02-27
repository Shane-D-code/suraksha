"""
threat_graph_engine.py - WITH REAL-TIME THREAT INTELLIGENCE
Person 3 — Graph & Threat Intelligence
Master orchestrator: wires all 6 services into one clean interface.

This is the single import that Person 2 (ML & Scoring Engineer) uses.
They call:
    result = await engine.analyze(domain)
And get back everything they need to build the final risk score.

Architecture:
    GraphUpdateService   → dynamic domain/IP insertion
    EmbeddingService     → inductive GNN embeddings
    SimilarityService    → FAISS similarity search
    CampaignDetector     → infrastructure campaign mapping
    DomainIntelService   → WHOIS/ASN/DNS/SSL enrichment
    ThreatDataLoader    → REAL-TIME threat intelligence (NEW!)
"""

import asyncio
import structlog
import networkx as nx
import logging
import json
import sys
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

from app.services.graph_update_service import GraphUpdateService, DomainNode
from app.services.embedding_service import EmbeddingService
from app.services.similarity_service import SimilarityService, SimilarDomain
from app.services.campaign_detector import CampaignDetector, DomainCampaignResult
from app.services.domain_intel_service import DomainIntelService, DomainIntelligence
from app.services.threat_data_loader import ThreatDataLoader, RealTimeThreatChecker, KNOWN_PHISHING_DOMAINS

logger = structlog.get_logger(__name__)


# ─── Output Schema ────────────────────────────────────────────────────────────

@dataclass
class ThreatGraphResult:
    """
    Full output from Person 3's analysis.
    Person 2 uses these fields to build the meta-model risk score.
    """
    domain: str

    # From EmbeddingService + SimilarityService
    gnn_score: float = 0.0
    similar_domains: list[SimilarDomain] = field(default_factory=list)
    cluster_probability: float = 0.0

    # From CampaignDetector
    campaign_id: Optional[str] = None
    campaign_size: int = 1
    in_campaign: bool = False

    # From DomainIntelService
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = None
    registrant_country: Optional[str] = None
    asn: Optional[str] = None
    ssl_issuer: Optional[str] = None
    ssl_valid: bool = False
    dns_ttl: Optional[int] = None
    is_established: bool = False
    intel_risk_score: float = 0.0

    # NEW: From Real-Time Threat Intelligence
    known_malicious: bool = False
    threat_category: Optional[str] = None
    threat_sources: list[str] = field(default_factory=list)

    # Combined signal for Person 2
    infrastructure_risk_score: float = 0.0   # GNN + campaign
    reputation_risk_score: float = 0.0       # WHOIS + ASN + SSL

    # Human-readable reasons (for explainability layer)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        # Deduplicate reasons while preserving order
        unique_reasons = []
        for r in self.reasons:
            if r and r not in unique_reasons:
                unique_reasons.append(r)

        return {
            "domain": self.domain,
            "gnn_score": round(self.gnn_score, 3),
            "cluster_probability": round(self.cluster_probability, 3),
            "campaign_id": self.campaign_id,
            "campaign_size": self.campaign_size,
            "in_campaign": self.in_campaign,
            "domain_age_days": self.domain_age_days,
            "registrar": self.registrar,
            "asn": self.asn,
            "ssl_issuer": self.ssl_issuer,
            "dns_ttl": self.dns_ttl,
            "is_established": self.is_established,
            "known_malicious": self.known_malicious,
            "threat_category": self.threat_category,
            "threat_sources": self.threat_sources,
            "infrastructure_risk_score": round(self.infrastructure_risk_score, 3),
            "reputation_risk_score": round(self.reputation_risk_score, 3),
            "similar_domains": [
                {"domain": s.domain, "similarity": round(s.similarity, 3)}
                for s in self.similar_domains[:3]
            ],
            "reasons": unique_reasons
        }


# Global engine instance
_engine: Optional['ThreatGraphEngine'] = None

async def init_threat_engine(db_pool, redis_client) -> 'ThreatGraphEngine':
    """Initialize the global ThreatGraphEngine."""
    global _engine
    if _engine is None:
        _engine = ThreatGraphEngine(db_pool, redis_client)
        await _engine.startup()
    return _engine

async def get_threat_engine() -> 'ThreatGraphEngine':
    """Get the global ThreatGraphEngine instance."""
    if _engine is None:
        raise RuntimeError("ThreatGraphEngine not initialized. Call init_threat_engine first.")
    return _engine


# ─── Threat Graph Engine ──────────────────────────────────────────────────────

class ThreatGraphEngine:
    """
    Person 3's main interface. Coordinates all intelligence services.
    
    NOW WITH REAL-TIME THREAT INTELLIGENCE!

    Lifecycle:
        engine = ThreatGraphEngine(db_pool, redis)
        await engine.startup()                  # on app boot
        result = await engine.analyze(domain)   # on every scan
        await engine.refresh_campaigns()         # scheduled, every 6hrs
        await engine.shutdown()                  # on app shutdown
    """

    def __init__(self, db_pool, redis_client=None,
                 model_path: str = "ml/models/gnn_model.pt"):
        self.db = db_pool
        self.redis = redis_client
        self._started = False

        # Initialize services
        self.graph_updater = GraphUpdateService(db_pool, redis_client)
        self.embedding_svc = EmbeddingService(model_path, redis_client=redis_client)
        self.similarity_svc = SimilarityService(db_pool=db_pool, redis_client=redis_client)
        self.campaign_detector = CampaignDetector(None, db_pool, redis_client)
        self.domain_intel = DomainIntelService(db_pool, redis_client)
        
        # NEW: Real-time threat intelligence
        self.threat_loader = ThreatDataLoader(db_pool, redis_client)
        self.realtime_checker = RealTimeThreatChecker(redis_client)

    async def startup(self):
        """
        Called once on FastAPI startup event.
        Loads graph, model, index in the correct dependency order.
        NOW ALSO LOADS REAL-TIME THREAT DATA!
        """
        if self._started:
            logger.warning("ThreatGraphEngine already started")
            return
            
        logger.info("ThreatGraphEngine: starting up with REAL-TIME intelligence...")

        # 0. Load real-time threat data
        threats = []
        try:
            threats = await self.threat_loader.load_initial_threat_data()
            logger.info(f"Loaded {len(threats)} real threat indicators")
        except Exception as e:
            logger.warning(f"Could not load threat data: {e}")

        # 1. Rebuild graph from DB
        await self.graph_updater.load_graph_from_db()

        # 1.5 Seed graph with new threats (if not already in DB)
        for t in threats:
            if t.domain not in self.graph_updater.graph:
                # Add basic node info so visualization and GNN can use it
                self.graph_updater.graph.add_node(
                    t.domain,
                    node_type="domain",
                    risk_label="MALICIOUS",
                    gnn_score=t.risk_score,
                    source=t.source
                )
                if t.ip:
                    ip_node = f"ip:{t.ip}"
                    self.graph_updater.graph.add_node(ip_node, node_type="ip")
                    self.graph_updater.graph.add_edge(t.domain, ip_node, relation="resolves_to")

        # 2. Load GNN model
        await self.embedding_svc.initialize()
        self.embedding_svc.set_graph(self.graph_updater.graph)

        # 3. Load similarity index
        await self.similarity_svc.initialize()

        # 4. Give campaign detector the graph
        self.campaign_detector.update_graph(self.graph_updater.graph)

        # 5. Run initial campaign detection
        await self.campaign_detector.detect_all_campaigns()

        self._started = True
        logger.info(f"ThreatGraphEngine ready. Known threats: {len(KNOWN_PHISHING_DOMAINS)}")

    async def shutdown(self):
        """Save index state on graceful shutdown."""
        if hasattr(self.similarity_svc, '_use_faiss') and self.similarity_svc._use_faiss:
            self.similarity_svc._save_faiss_index()
        logger.info("ThreatGraphEngine: shutdown complete")

    # ── Main Analysis ─────────────────────────────────────────────────────────

    async def analyze(self, domain_or_url: str, text: Optional[str] = None, 
                      html: Optional[str] = None, risk_label: str = "UNKNOWN") -> ThreatGraphResult:
        """Main entry point: multi-track threat analysis."""
        sys.stdout.write(f"PHISHGUARD_DEBUG: analyze called for {domain_or_url}\n")
        sys.stdout.flush()
        if not self._started:
            await self.startup()
        # Extract hostname if full URL provided
        domain = domain_or_url
        if "://" in domain:
            from urllib.parse import urlparse
            try:
                domain = urlparse(domain).netloc
                # Remove port if present
                if ":" in domain:
                    domain = domain.split(":")[0]
            except Exception:
                pass

        result = ThreatGraphResult(domain=domain)
        logger.info(f"Analyzing domain: {domain} (original: {domain_or_url})")

        # Track 0: REAL-TIME THREAT CHECK (FASTEST!)
        try:
            reputation = await self.threat_loader.get_domain_reputation(domain)
            if reputation.get("risk_score", 0) > 0.5:
                result.known_malicious = True
                result.threat_category = reputation.get("threat_type", "phishing")
                result.threat_sources = reputation.get("sources", [])
                result.intel_risk_score = max(result.intel_risk_score, reputation.get("risk_score", 0))
                logger.info(f"REAL-TIME HIT: {domain} is known {result.threat_category}!")
        except Exception as e:
            logger.debug(f"Real-time check failed: {e}")

        # Track A + B + C in parallel
        track_a, track_b, track_c = await asyncio.gather(
            self._track_graph(domain, risk_label),
            self.domain_intel.enrich(domain),
            self.campaign_detector.get_domain_campaign(domain),
            return_exceptions=True
        )

        # Apply Track A (graph + embedding + similarity)
        if isinstance(track_a, dict):
            result.gnn_score = track_a.get("gnn_score", 0.0)
            result.similar_domains = track_a.get("similar_domains", [])
            result.cluster_probability = track_a.get("cluster_probability", 0.0)
        elif isinstance(track_a, Exception):
            logger.error(f"Graph track failed for {domain}: {track_a}")

        # Apply Track B (domain intelligence)
        if isinstance(track_b, DomainIntelligence):
            result.domain_age_days = track_b.domain_age_days
            result.registrar = track_b.registrar
            result.registrant_country = track_b.registrant_country
            result.asn = track_b.asn
            result.ssl_issuer = track_b.ssl_issuer
            result.ssl_valid = track_b.ssl_valid
            result.dns_ttl = track_b.dns_ttl
            result.is_established = track_b.is_established
            result.intel_risk_score = max(result.intel_risk_score, track_b.risk_score)
            result.reasons.extend(track_b.risk_reasons)
        elif isinstance(track_b, Exception):
            logger.error(f"Intel track failed for {domain}: {track_b}")

        # Apply Track C (campaign)
        if not isinstance(track_c, Exception):
            result.campaign_id = track_c.campaign_id
            result.campaign_size = track_c.campaign_size
            result.in_campaign = track_c.cluster_probability > 0.3
            if track_c.cluster_probability > 0.3:
                result.reasons.append(track_c.reason)

        # Compute composite scores for Person 2
        result.infrastructure_risk_score = self._compute_infra_score(result)
        result.reputation_risk_score = result.intel_risk_score
        
        # If known malicious, boost scores significantly
        if result.known_malicious:
            result.infrastructure_risk_score = max(result.infrastructure_risk_score, 0.85)
            result.reputation_risk_score = max(result.reputation_risk_score, 0.95)

        # Add infrastructure reasons
        self._add_infra_reasons(result)

        # Update graph with final risk label
        final_label = self._determine_label(result)
        
        # Get embedding and update similarity index
        try:
            embedding, gnn_prediction = await self.embedding_svc.get_embedding(domain)
            result.gnn_score = max(result.gnn_score, gnn_prediction)
            
            await self.similarity_svc.add_embedding(
                domain,
                embedding,
                gnn_score=gnn_prediction,
                risk_label=final_label
            )
        except Exception as e:
            logger.warning(f"Failed to update embedding for {domain}: {e}")

        # CRITICAL: Update graph with final risk label and computed gnn_score
        try:
            # Use the computed infrastructure_risk_score as gnn_score for the graph
            await self.graph_updater.update_after_scan(
                domain, 
                final_label, 
                gnn_score=result.infrastructure_risk_score
            )
            logger.info(f"Graph updated with final label: {domain} -> {final_label} (score: {result.infrastructure_risk_score:.3f})")
        except Exception as e:
            logger.warning(f"Failed to update graph with final label for {domain}: {e}")

        # Final deduplication of reasons
        seen = set()
        unique = []
        for r in result.reasons:
            if r and r not in seen:
                unique.append(r)
                seen.add(r)
        result.reasons = unique

        return result

    # ── Internal Tracks ───────────────────────────────────────────────────────

    async def _track_graph(self, domain: str, risk_label: str) -> dict:
        """Graph update → embedding → similarity, in series (each depends on previous)."""
        
        # Sync embedding service with current graph (before update)
        self.embedding_svc.set_graph(self.graph_updater.graph)
        self.campaign_detector.update_graph(self.graph_updater.graph)

        # 1. Generate embedding + score FIRST (needed for graph update)
        embedding, gnn_prediction = await self.embedding_svc.get_embedding(domain)
        
        # 2. Find similar domains + cluster risk
        similar = await self.similarity_svc.find_similar(domain, embedding, k=5)
        cluster = await self.similarity_svc.get_cluster_risk(domain, embedding)

        # GNN score = mix of direct prediction + similarity-based score
        # If similar domains are known malicious, boost the sim_score
        top_malicious = [s for s in similar if s.risk_label in ("HIGH", "MALICIOUS")]
        sim_score = 0.0
        if top_malicious:
            # Weight by similarity and give a floor to gnn_score for known malicious artifacts
            weights = []
            for s in top_malicious[:3]:
                # If label is MALICIOUS, it means it's a confirmed threat
                effective_score = max(s.gnn_score, 0.85 if s.risk_label == "MALICIOUS" else 0.6)
                weights.append(s.similarity * effective_score)
                logger.debug(f"Similar malicious: {s.domain} (label={s.risk_label}, sim={s.similarity:.3f}, gnn={s.gnn_score:.3f} -> effective={effective_score:.3f})")
            
            sim_score = sum(weights) / len(weights)
            msg = f"PHISHGUARD_DEBUG: Boosted by similarity: sim_score={sim_score:.3f} (n={len(top_malicious)})\n"
            sys.stdout.write(msg)
            sys.stdout.flush()

        # Weighted fusion: direct GNN prediction is valuable, but similarity is safer for zero-days
        final_gnn_score = (gnn_prediction * 0.4) + (sim_score * 0.6)
        final_gnn_score = min(final_gnn_score, 1.0)
        
        msg = f"PHISHGUARD_DEBUG: GNN Track result for {domain}: prediction={gnn_prediction:.3f}, sim_boost={sim_score:.3f}, final={final_gnn_score:.3f}\n"
        sys.stdout.write(msg)
        sys.stdout.flush()

        # 3. NOW update graph with the computed gnn_score
        node = await self.graph_updater.update_after_scan(domain, risk_label, gnn_score=final_gnn_score)

        return {
            "gnn_score": final_gnn_score,
            "similar_domains": similar,
            "cluster_probability": cluster["cluster_probability"]
        }

    # ── Score Computation ─────────────────────────────────────────────────────

    def _compute_infra_score(self, result: ThreatGraphResult) -> float:
        """
        Combines GNN + campaign signals into infrastructure risk score.
        Person 2 uses this as one input to the meta-model.
        """
        score = 0.0
        score += result.gnn_score * 0.5
        score += result.cluster_probability * 0.3
        if result.in_campaign:
            campaign_boost = min((result.campaign_size - 1) / 10.0, 0.2)
            score += campaign_boost
        
        # If known malicious, boost score
        if result.known_malicious:
            score = max(score, 0.85)
            
        return min(score, 1.0)

    def _add_infra_reasons(self, result: ThreatGraphResult):
        # Add known malicious warning first
        if result.known_malicious:
            result.reasons.insert(0, f"⚠️ KNOWN {result.threat_category.upper()} - Found in threat database!")
        
        if result.gnn_score > 0.6:
            result.reasons.append(
                f"GNN infrastructure similarity to known malicious domains: {result.gnn_score:.2f}"
            )
        if result.cluster_probability > 0.5:
            result.reasons.append(
                f"Clusters with {int(result.cluster_probability * 3)} malicious domain(s)"
            )
        if result.similar_domains:
            top = result.similar_domains[0]
            if top.similarity > 0.85 and top.risk_label in ("HIGH", "MALICIOUS"):
                result.reasons.append(
                    f"Infrastructure nearly identical to {top.domain} ({top.similarity:.2f} similarity)"
                )

    def _determine_label(self, result: ThreatGraphResult) -> str:
        if result.known_malicious:
            return "MALICIOUS"
            
        combined = (result.infrastructure_risk_score + result.reputation_risk_score) / 2
        if combined >= 0.7:
            return "HIGH"
        elif combined >= 0.4:
            return "MEDIUM"
        return "LOW"

    # ── Scheduled Jobs ───────────────────────────────────────────────────────

    async def refresh_campaigns(self):
        """
        Run this via Celery beat every 6 hours.
        Keeps campaign detection current as graph grows.
        """
        logger.info("Campaign refresh starting...")
        campaigns = await self.campaign_detector.detect_all_campaigns()
        logger.info(f"Campaign refresh complete: {len(campaigns)} campaigns")
        return len(campaigns)

    # ── Status & Health ───────────────────────────────────────────────────────

    def get_visualization_data(self, limit: int = 50) -> dict:
        """Export subgraph for frontend D3/Sigma.js visualization."""
        graph = self.graph_updater.graph
        
        # Take top nodes with highest risk
        nodes = []
        node_ids = set()
        
        # Get all nodes with risk
        all_nodes = []
        for n, d in graph.nodes(data=True):
            all_nodes.append((n, d))
        
        # Sort by gnn_score descending
        all_nodes.sort(key=lambda x: x[1].get("gnn_score", 0.0), reverse=True)
        
        # Take top nodes
        for n, d in all_nodes[:limit]:
            nodes.append({
                "id": str(n),
                "label": str(n).replace("domain:", "").replace("ip:", "").replace("cert:", ""),
                "type": d.get("node_type", "unknown"),
                "risk": d.get("gnn_score", 0.0)
            })
            node_ids.add(n)

        # Get edges between these nodes
        edges = []
        for u, v, d in graph.edges(data=True):
            if u in node_ids and v in node_ids:
                edges.append({
                    "source": str(u),
                    "target": str(v),
                    "type": d.get("edge_type", "linked")
                })

        return {"nodes": nodes, "edges": edges}

    def health_check(self) -> dict:
        return {
            "graph": self.graph_updater.graph_stats(),
            "similarity_index": self.similarity_svc.status(),
            "campaigns": self.campaign_detector.get_stats(),
            "model_loaded": self.embedding_svc.model is not None,
            "known_threats": len(KNOWN_PHISHING_DOMAINS),
            "realtime_intel": True,
            "started": self._started,
        }
