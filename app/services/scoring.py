"""
Scoring and fusion engine for combining model and graph scores.
Recalibrated v2.0 - Enhanced risk scoring with infrastructure boosts and escalation rules.
v3.0 - Clean tiered reasons system for enterprise-grade readability.
"""
from typing import Tuple, List, Optional
import structlog

from app.config import settings
from app.models.schemas import RiskLevel

logger = structlog.get_logger(__name__)


# ============================================================
# REASON TIER SYSTEM v3.0
# ============================================================
# Enterprise-grade readable reasons organized by severity:
#
# 🔴 CRITICAL (Tier 1) - Immediate action required
# 🟠 WARNING (Tier 2) - Review recommended  
# 🟢 INFO (Tier 3) - Informational only

REASON_TIERS = {
    # Critical reasons - HIGH risk
    "KNOWN_MALICIOUS": {
        "tier": "🔴",
        "level": "CRITICAL",
        "message": "Known malicious domain"
    },
    "INFRASTRUCTURE_MATCHES_PHISHING_CLUSTER": {
        "tier": "🔴", 
        "level": "CRITICAL",
        "message": "Infrastructure matches phishing cluster"
    },
    "CAMPAIGN_PARTICIPATION": {
        "tier": "🔴",
        "level": "CRITICAL", 
        "message": "Part of active phishing campaign"
    },
    
    # Warning reasons - MEDIUM risk indicators
    "SUSPICIOUS_TLD": {
        "tier": "🟠",
        "level": "WARNING",
        "message": "Suspicious top-level domain"
    },
    "NEW_DOMAIN": {
        "tier": "🟠",
        "level": "WARNING",
        "message": "Recently registered domain"
    },
    "NO_SSL": {
        "tier": "🟠",
        "level": "WARNING", 
        "message": "Invalid or missing SSL certificate"
    },
    "FAST_FLUX_DNS": {
        "tier": "🟠",
        "level": "WARNING",
        "message": "Fast-flux DNS detected"
    },
    "HIGH_ML_CONFIDENCE": {
        "tier": "🟠",
        "level": "WARNING",
        "message": "High phishing text confidence"
    },
    "MODERATE_ML_CONFIDENCE": {
        "tier": "🟠",
        "level": "WARNING",
        "message": "Moderate phishing indicators detected"
    },
    "STRONG_INFRA_INDICATORS": {
        "tier": "🟠",
        "level": "WARNING",
        "message": "Strong infrastructure threat indicators"
    },
    "SOME_INFRA_INDICATORS": {
        "tier": "🟠",
        "level": "WARNING",
        "message": "Some infrastructure threat indicators"
    },
    
    # Info reasons - LOW risk / benign
    "LOW_ML_CONFIDENCE": {
        "tier": "🟢",
        "level": "INFO",
        "message": "Content appears benign"
    },
    "NO_INFRA_INDICATORS": {
        "tier": "🟢",
        "level": "INFO",
        "message": "No significant infrastructure threats"
    },
    "DOMAIN_AGE_UNKNOWN": {
        "tier": "🟢",
        "level": "INFO",
        "message": "Domain age could not be determined"
    },
}


def _convert_reason_to_tiered(reason: str) -> str:
    """
    Convert legacy reason strings to user-friendly tiered format.
    Maps technical reasons to simple, understandable language.
    """
    reason_lower = reason.lower()
    
    # Critical mappings - High danger
    if "known malicious" in reason_lower:
        return "🔴 Known dangerous website"
    if "campaign" in reason_lower:
        return "🔴 Part of active scam campaign"
    if "cluster" in reason_lower and "similar" in reason_lower:
        return "🔴 Linked to known phishing sites"
    if "infrastructure nearly identical" in reason_lower:
        return "🔴 Nearly identical to phishing sites"
    if "gnn infrastructure similarity" in reason_lower:
        return "🔴 Matches known threat network"
        
    # Warning mappings - Medium concern (simplified!)
    if "suspicious tld" in reason_lower:
        return "⚠️ Suspicious domain ending"
    if "new domain" in reason_lower or "very new domain" in reason_lower:
        return "⚠️ Very new website (less than 7 days old)"
    if "domain age could not be determined" in reason_lower:
        return "⚠️ Website age unknown"
    if "no valid ssl" in reason_lower or "ssl" in reason_lower:
        return "⚠️ No secure connection (missing HTTPS)"
    if "fast-flux" in reason_lower or "ttl=" in reason_lower:
        return "⚠️ Suspicious DNS behavior"
    if "very high ml" in reason_lower:
        return "⚠️ High probability of phishing"
    if "high ml" in reason_lower:
        return "⚠️ Signs of phishing detected"
    if "moderate ml" in reason_lower:
        return "⚠️ Some suspicious elements found"
    if "strong infrastructure" in reason_lower:
        return "⚠️ Questionable server setup"
    if "some infrastructure" in reason_lower:
        return "⚠️ Some server warnings"
    if "composite escalation" in reason_lower:
        return "⚠️ Multiple warning signs detected"
    if "fast-flux dns auto-escalated" in reason_lower:
        return "⚠️ Automatic warning raised"
        
    # Info mappings - Low/Good
    if "low ml" in reason_lower and "benign" in reason_lower:
        return "✓ Page content looks safe"
    if "no significant infrastructure" in reason_lower:
        return "✓ No server warnings"
    if "appears safe" in reason_lower or "domain appears safe" in reason_lower:
        return "✓ Website appears legitimate"
        
    # Risk level summaries - Simplified!
    if "high risk level" in reason_lower:
        return "🔴 HIGH RISK: Don't proceed"
    if "medium risk level" in reason_lower:
        return "⚠️ CAUTION: Proceed with care"
    if "low risk level" in reason_lower:
        return "✓ LOW RISK: Looks safe"
        
    # Return original if no mapping found
    return reason


def _tier_reasons(reasons: List[str]) -> List[str]:
    """
    Convert a list of reasons to tiered format and sort by tier.
    Critical (🔴) first, then Warning (⚠️), then Info (✓).
    Limits to max 4 reasons for clarity.
    """
    tiered_reasons = [_convert_reason_to_tiered(r) for r in reasons if r]
    
    # Sort by tier: 🔴 > ⚠️ > ✓
    tier_order = {"🔴": 0, "⚠️": 1, "✓": 2}
    
    def get_tier_sort(r: str) -> int:
        for tier, order in tier_order.items():
            if r.startswith(tier):
                return order
        return 3  # Unknown tier goes last
    
    tiered_reasons.sort(key=get_tier_sort)
    
    # Deduplicate while preserving order
    unique_reasons = []
    seen = set()
    for r in tiered_reasons:
        if r and r not in seen:
            unique_reasons.append(r)
            seen.add(r)
    
    # Limit to max 4 reasons for clarity
    if len(unique_reasons) > 4:
        return unique_reasons[:4]
    
    return unique_reasons


def compute_final_score(
    model_score: float,
    graph_score: float,
    reputation_risk_score: float = 0.0,
    infrastructure_risk_score: float = 0.0,
    dns_ttl: Optional[int] = None,
    ssl_valid: bool = True,
    domain_age_days: Optional[int] = None,
    known_malicious: bool = False,
    suspicious_tld: bool = False,
    campaign_participation: bool = False,
) -> Tuple[RiskLevel, float, List[str]]:
    """
    Compute final risk score with separated content and infrastructure layers.
    
    Architecture:
    - content_risk: Directly from ML model (phishing content detection)
    - infrastructure_risk: Weighted combination of graph, reputation, DNS, SSL, age
    
    Args:
        model_score: ML model score (0-1) - content-level phishing detection
        graph_score: GNN + similarity score (0-1)
        reputation_risk_score: WHOIS/ASN/SSL reputation (0-1)
        infrastructure_risk_score: Base infrastructure risk from graph + campaign
        dns_ttl: DNS TTL in seconds (fast-flux indicator if <= 60)
        ssl_valid: SSL certificate validity
        domain_age_days: Domain age in days (suspicious if < 7)
        known_malicious: Flag if domain is in known malicious list
        suspicious_tld: Flag if TLD is suspicious (.tk, .ml, .xyz, etc.)
        campaign_participation: Flag if domain part of known campaign
    
    Returns:
        Tuple of (risk_level, confidence, reasons)
    """
    # Normalize all scores to [0, 1] with None handling
    model_score = _normalize_score(model_score)
    graph_score = _normalize_score(graph_score)
    reputation_risk_score = _normalize_score(reputation_risk_score)
    infrastructure_risk_score = _normalize_score(infrastructure_risk_score)
    
    # ==========================================
    # 1️⃣ SEPARATE INTERNAL RISK LAYERS
    # ==========================================
    
    # Content risk: Direct ML model output (phishing content detection)
    content_risk = model_score
    
    # Infrastructure risk: Weighted combination of multiple signals
    # Base: graph_score (40%) + reputation (30%) + existing infra score (30%)
    infrastructure_risk = (
        graph_score * 0.40 +
        reputation_risk_score * 0.30 +
        infrastructure_risk_score * 0.30
    )
    
    # ==========================================
    # 2️⃣ INFRASTRUCTURE BOOST RULES
    # ==========================================
    
    reasons = []  # Track which boosts are applied
    
    # Known malicious: Force minimum 0.9 infrastructure risk
    if known_malicious:
        infrastructure_risk = max(infrastructure_risk, 0.9)
        reasons.append("⚠️ KNOWN MALICIOUS - Found in threat database!")
    
    # Fast-flux DNS detection (TTL <= 60 seconds)
    if dns_ttl is not None and dns_ttl <= 60:
        infrastructure_risk = min(infrastructure_risk + 0.25, 1.0)
        reasons.append(f"Fast-flux DNS detected (TTL={dns_ttl}s)")
    
    # Invalid SSL certificate
    if not ssl_valid:
        infrastructure_risk = min(infrastructure_risk + 0.15, 1.0)
        reasons.append("No valid SSL certificate — unencrypted or certificate error")
    
    # New domain (less than 7 days old) or unknown age
    if domain_age_days is None or domain_age_days < 7:
        infrastructure_risk = min(infrastructure_risk + 0.15, 1.0)
        if domain_age_days is not None:
            reasons.append(f"Very new domain (age: {domain_age_days} days)")
        else:
            reasons.append("Domain age could not be determined")
    
    # Campaign participation boost
    if campaign_participation:
        infrastructure_risk = min(infrastructure_risk + 0.20, 1.0)
        reasons.append("Domain linked to active phishing campaign")
    
    # Cap infrastructure risk at 1.0
    infrastructure_risk = min(infrastructure_risk, 1.0)
    
    # ==========================================
    # FINAL SCORE COMPUTATION (50/50 split)
    # ==========================================
    
    final_score = (content_risk * 0.5) + (infrastructure_risk * 0.5)
    
    # ==========================================
    # 3️⃣ HIGH CONFIDENCE ESCALATION RULE
    # ==========================================
    
    if model_score >= 0.9 and suspicious_tld:
        final_score = max(final_score, 0.8)
        reasons.append("High ML confidence + suspicious TLD escalation")
    
    # ==========================================
    # 4️⃣ COMPOSITE ESCALATION RULE
    # ==========================================
    
    composite_flags = [
        suspicious_tld,
        not ssl_valid,
        (domain_age_days is None or domain_age_days < 7),
        (dns_ttl is not None and dns_ttl <= 60)
    ]
    composite_count = sum(1 for flag in composite_flags if flag)
    
    if composite_count >= 3:
        final_score = max(final_score, 0.85)
        reasons.append(f"Multiple suspicious indicators ({composite_count}/4) — composite escalation")
    
    # ==========================================
    # 5️⃣ RISK CLASSIFICATION THRESHOLDS
    # ==========================================
    
    if final_score >= 0.75:
        risk_level = RiskLevel.HIGH
    elif final_score >= 0.45:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW
    
    # ==========================================
    # 6️⃣ REASON CONSISTENCY CHECKS
    # ==========================================
    
    # Rule: If known_malicious, risk MUST be HIGH
    if known_malicious and risk_level != RiskLevel.HIGH:
        risk_level = RiskLevel.HIGH
        final_score = max(final_score, 0.9)
        logger.warning("Risk escalation: known_malicious forced to HIGH", final_score=final_score)
    
    # Rule: If DNS fast-flux and risk is LOW, escalate to MEDIUM minimum
    if (dns_ttl is not None and dns_ttl <= 60) and risk_level == RiskLevel.LOW:
        risk_level = RiskLevel.MEDIUM
        final_score = max(final_score, 0.45)
        reasons.append("Fast-flux DNS auto-escalated risk to MEDIUM")
        logger.warning("Risk escalation: fast-flux DNS forced to MEDIUM", final_score=final_score)
    
    # ==========================================
    # CONFIDENCE CALCULATION
    # ==========================================
    
    # Higher confidence when content and infrastructure risks agree
    score_diff = abs(content_risk - infrastructure_risk)
    confidence = 1.0 - (score_diff / 2.0)
    
    # Boost confidence if known_malicious (high certainty)
    if known_malicious:
        confidence = max(confidence, 0.95)
    
    # ==========================================
    # GENERATE COMPLETE REASONS LIST
    # ==========================================
    
    # Add content-level reasons
    if model_score >= 0.9:
        reasons.append("Very high ML model confidence for malicious content")
    elif model_score >= 0.7:
        reasons.append("High ML model confidence for malicious content")
    elif model_score >= 0.4:
        reasons.append("Moderate ML model confidence")
    else:
        reasons.append("Low ML model confidence — content appears benign")
    
    # Add infrastructure-level reasons
    if infrastructure_risk >= 0.7:
        reasons.append("Strong infrastructure threat indicators")
    elif infrastructure_risk >= 0.4:
        reasons.append("Some infrastructure threat indicators")
    else:
        reasons.append("No significant infrastructure threat indicators")
    
    # Add risk level summary
    if risk_level == RiskLevel.HIGH:
        reasons.append("HIGH risk level: immediate attention recommended")
    elif risk_level == RiskLevel.MEDIUM:
        reasons.append("MEDIUM risk level: review recommended")
    else:
        reasons.append("LOW risk level: appears safe")
    
    # Convert to tiered reasons for enterprise-grade readability
    unique_reasons = _tier_reasons(reasons)
    
    logger.info(
        "Score computed v2.0",
        content_risk=round(content_risk, 3),
        infrastructure_risk=round(infrastructure_risk, 3),
        final_score=round(final_score, 3),
        risk_level=risk_level.value,
        composite_flags=composite_count,
        known_malicious=known_malicious,
    )
    
    return risk_level, round(confidence, 2), unique_reasons


def _normalize_score(score: Optional[float], default: float = 0.0) -> float:
    """
    Safely normalize a score to [0, 1] range.
    Handles None, NaN, and out-of-range values.
    """
    if score is None:
        return default
    try:
        score = float(score)
        if score != score:  # NaN check
            return default
        return max(0.0, min(1.0, score))
    except (TypeError, ValueError):
        return default


def _generate_legacy_reasons(
    model_score: float,
    graph_score: float,
    risk_level: RiskLevel,
) -> List[str]:
    """
    Legacy reason generator for backward compatibility.
    Deprecated: Use compute_final_score with full parameters instead.
    """
    reasons = []
    
    if model_score >= 0.7:
        reasons.append("High ML model confidence for malicious content")
    elif model_score >= 0.4:
        reasons.append("Moderate ML model confidence")
    else:
        reasons.append("Low ML model confidence")
    
    if graph_score >= 0.7:
        reasons.append("Strong graph-based threat indicators")
    elif graph_score >= 0.4:
        reasons.append("Some graph-based threat indicators")
    else:
        reasons.append("No significant graph threat indicators")
    
    if risk_level == RiskLevel.HIGH:
        reasons.append("HIGH risk level: immediate attention recommended")
    elif risk_level == RiskLevel.MEDIUM:
        reasons.append("MEDIUM risk level: review recommended")
    else:
        reasons.append("LOW risk level: content appears benign")
    
    return reasons


def normalize_score(score: float, min_val: float = 0.0, max_val: float = 1.0) -> float:
    """Normalize score to [0, 1] range."""
    if max_val == min_val:
        return 0.5
    return max(0.0, min(1.0, (score - min_val) / (max_val - min_val)))


def apply_threshold(score: float, thresholds: dict) -> RiskLevel:
    """Apply thresholds to determine risk level."""
    if score >= thresholds.get("high", 0.7):
        return RiskLevel.HIGH
    elif score >= thresholds.get("medium", 0.4):
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def calculate_entropy(scores: List[float]) -> float:
    """Calculate entropy of a probability distribution."""
    if not scores:
        return 0.0
    
    # Normalize scores to probabilities
    total = sum(scores)
    if total == 0:
        return 0.0
    
    probs = [s / total for s in scores]
    
    # Calculate entropy
    import math
    entropy = 0.0
    for p in probs:
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy


def compute_domain_only_score(
    graph_score: float,
    reputation_risk_score: float = 0.0,
    infrastructure_risk_score: float = 0.0,
    dns_ttl: Optional[int] = None,
    ssl_valid: bool = True,
    domain_age_days: Optional[int] = None,
    known_malicious: bool = False,
    suspicious_tld: bool = False,
    campaign_participation: bool = False,
) -> Tuple[RiskLevel, float, List[str], float]:
    """
    Fast domain-only scoring for pre-navigation browser blocking.
    
    Optimized for <300ms response time by skipping:
    - HTML fetching
    - ML text classification
    - Content analysis
    
    Architecture:
    - content_risk = 0 (no content analysis)
    - infrastructure_risk = weighted combination of all domain signals
    - final_score = infrastructure_risk (100% weight on infrastructure)
    
    Args:
        graph_score: GNN + similarity score (0-1)
        reputation_risk_score: WHOIS/ASN/SSL reputation (0-1)
        infrastructure_risk_score: Base infrastructure risk from graph + campaign
        dns_ttl: DNS TTL in seconds (fast-flux indicator if <= 60)
        ssl_valid: SSL certificate validity
        domain_age_days: Domain age in days (suspicious if < 7)
        known_malicious: Flag if domain is in known malicious list
        suspicious_tld: Flag if TLD is suspicious (.tk, .ml, .xyz, etc.)
        campaign_participation: Flag if domain part of known campaign
    
    Returns:
        Tuple of (risk_level, confidence, reasons, final_score)
    """
    # Normalize all scores to [0, 1] with None handling
    graph_score = _normalize_score(graph_score)
    reputation_risk_score = _normalize_score(reputation_risk_score)
    infrastructure_risk_score = _normalize_score(infrastructure_risk_score)
    
    # ==========================================
    # INFRASTRUCTURE RISK COMPUTATION
    # ==========================================
    
    # Base: weighted combination of signals
    infrastructure_risk = (
        graph_score * 0.40 +
        reputation_risk_score * 0.30 +
        infrastructure_risk_score * 0.30
    )
    
    reasons = []
    
    # Known malicious: Force minimum 0.9 infrastructure risk
    if known_malicious:
        infrastructure_risk = max(infrastructure_risk, 0.9)
        reasons.append("⚠️ KNOWN MALICIOUS - Found in threat database!")
    
    # Fast-flux DNS detection (TTL <= 60 seconds)
    if dns_ttl is not None and dns_ttl <= 60:
        infrastructure_risk = min(infrastructure_risk + 0.25, 1.0)
        reasons.append(f"Fast-flux DNS detected (TTL={dns_ttl}s)")
    
    # Invalid SSL certificate
    if not ssl_valid:
        infrastructure_risk = min(infrastructure_risk + 0.15, 1.0)
        reasons.append("No valid SSL certificate — unencrypted or certificate error")
    
    # New domain (less than 7 days old) or unknown age
    if domain_age_days is None or domain_age_days < 7:
        infrastructure_risk = min(infrastructure_risk + 0.15, 1.0)
        if domain_age_days is not None:
            reasons.append(f"Very new domain (age: {domain_age_days} days)")
        else:
            reasons.append("Domain age could not be determined")
    
    # Campaign participation boost
    if campaign_participation:
        infrastructure_risk = min(infrastructure_risk + 0.20, 1.0)
        reasons.append("Domain linked to active phishing campaign")
    
    # Cap infrastructure risk at 1.0
    infrastructure_risk = min(infrastructure_risk, 1.0)
    
    # ==========================================
    # FINAL SCORE (Domain-only: 100% infrastructure)
    # ==========================================
    
    final_score = infrastructure_risk  # No content risk in domain-only mode
    
    # ==========================================
    # RISK CLASSIFICATION (Domain-only thresholds)
    # ==========================================
    
    if final_score >= 0.75:
        risk_level = RiskLevel.HIGH
    elif final_score >= 0.45:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW
    
    # ==========================================
    # HARD BLOCKING RULE
    # ==========================================
    
    # If known_malicious, always HIGH (override any other logic)
    if known_malicious and risk_level != RiskLevel.HIGH:
        risk_level = RiskLevel.HIGH
        final_score = max(final_score, 0.9)
        reasons.append("Known malicious domain — forced HIGH risk")
    
    # ==========================================
    # CONFIDENCE CALCULATION
    # ==========================================
    
    # High confidence for known malicious
    confidence = 0.95 if known_malicious else 0.75
    
    # ==========================================
    # GENERATE REASONS
    # ==========================================
    
    # Add infrastructure-level reasons
    if infrastructure_risk >= 0.7:
        reasons.append("Strong infrastructure threat indicators")
    elif infrastructure_risk >= 0.4:
        reasons.append("Some infrastructure threat indicators")
    else:
        reasons.append("No significant infrastructure threat indicators")
    
    # Add risk level summary
    if risk_level == RiskLevel.HIGH:
        reasons.append("HIGH risk level: immediate attention recommended")
    elif risk_level == RiskLevel.MEDIUM:
        reasons.append("MEDIUM risk level: review recommended")
    else:
        reasons.append("LOW risk level: domain appears safe")
    
    # Convert to tiered reasons for enterprise-grade readability
    unique_reasons = _tier_reasons(reasons)
    
    logger.info(
        "Domain-only score computed",
        infrastructure_risk=round(infrastructure_risk, 3),
        final_score=round(final_score, 3),
        risk_level=risk_level.value,
        known_malicious=known_malicious,
    )
    
    return risk_level, round(confidence, 2), unique_reasons, final_score


def compute_fast_url_score(
    url_model_score: float,
    graph_score: float,
    reputation_risk_score: float = 0.0,
    infrastructure_risk_score: float = 0.0,
    dns_ttl: Optional[int] = None,
    ssl_valid: bool = True,
    domain_age_days: Optional[int] = None,
    known_malicious: bool = False,
    suspicious_tld: bool = False,
    campaign_participation: bool = False,
) -> Tuple[RiskLevel, float, List[str], float]:
    """
    Fast URL-based scoring for pre-navigation browser blocking.
    
    Optimized for <100ms response time by:
    - Using URL-based ML analysis (fast pattern matching, no HTTP request)
    - Skipping HTML/content fetching
    - Using same scoring formula as full analysis
    
    This provides CONSISTENT results with investigate endpoint while remaining fast.
    """
    # Normalize all scores to [0, 1] with None handling
    url_model_score = _normalize_score(url_model_score)
    graph_score = _normalize_score(graph_score)
    reputation_risk_score = _normalize_score(reputation_risk_score)
    infrastructure_risk_score = _normalize_score(infrastructure_risk_score)
    
    # Content risk (from URL analysis only - fast!)
    content_risk = url_model_score
    
    # Infrastructure risk computation
    infrastructure_risk = (
        graph_score * 0.40 +
        reputation_risk_score * 0.30 +
        infrastructure_risk_score * 0.30
    )
    
    reasons = []
    
    # Known malicious: Force minimum 0.9 infrastructure risk
    if known_malicious:
        infrastructure_risk = max(infrastructure_risk, 0.9)
        reasons.append("KNOWN MALICIOUS - Found in threat database!")
    
    # Fast-flux DNS detection
    if dns_ttl is not None and dns_ttl <= 60:
        infrastructure_risk = min(infrastructure_risk + 0.25, 1.0)
        reasons.append(f"Fast-flux DNS detected (TTL={dns_ttl}s)")
    
    # Invalid SSL certificate
    if not ssl_valid:
        infrastructure_risk = min(infrastructure_risk + 0.15, 1.0)
        reasons.append("No valid SSL certificate")
    
    # New domain
    if domain_age_days is None or domain_age_days < 7:
        infrastructure_risk = min(infrastructure_risk + 0.15, 1.0)
        if domain_age_days is not None:
            reasons.append(f"Very new domain (age: {domain_age_days} days)")
        else:
            reasons.append("Domain age could not be determined")
    
    # Campaign participation
    if campaign_participation:
        infrastructure_risk = min(infrastructure_risk + 0.20, 1.0)
        reasons.append("Domain linked to active phishing campaign")
    
    infrastructure_risk = min(infrastructure_risk, 1.0)
    
    # Final score (50/50 like full analysis)
    final_score = (content_risk * 0.5) + (infrastructure_risk * 0.5)
    
    # Apply same boosts as full analysis
    if known_malicious:
        final_score = max(final_score, 0.9)
    if url_model_score >= 0.9 and suspicious_tld:
        final_score = max(final_score, 0.8)
        reasons.append("High ML confidence + suspicious TLD escalation")
    
    # Composite escalation
    composite_flags = [
        suspicious_tld,
        not ssl_valid,
        (domain_age_days is None or domain_age_days < 7),
        (dns_ttl is not None and dns_ttl <= 60)
    ]
    composite_count = sum(1 for flag in composite_flags if flag)
    if composite_count >= 3:
        final_score = max(final_score, 0.85)
        reasons.append(f"Multiple suspicious indicators ({composite_count}/4)")
    
    final_score = min(final_score, 1.0)
    
    # Risk classification (same as full!)
    if final_score >= 0.75:
        risk_level = RiskLevel.HIGH
    elif final_score >= 0.45:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW
    
    # Hard blocking rule
    if known_malicious and risk_level != RiskLevel.HIGH:
        risk_level = RiskLevel.HIGH
        final_score = max(final_score, 0.9)
        reasons.append("Known malicious domain - forced HIGH risk")
    
    # Confidence calculation
    score_diff = abs(content_risk - infrastructure_risk)
    confidence = 1.0 - (score_diff / 2.0)
    if known_malicious:
        confidence = max(confidence, 0.95)
    
    # Generate reasons
    if url_model_score >= 0.9:
        reasons.append("Very high ML model confidence for malicious URL")
    elif url_model_score >= 0.7:
        reasons.append("High ML model confidence for malicious URL")
    elif url_model_score >= 0.4:
        reasons.append("Moderate ML model confidence")
    else:
        reasons.append("Low ML model confidence - URL appears benign")
    
    if infrastructure_risk >= 0.7:
        reasons.append("Strong infrastructure threat indicators")
    elif infrastructure_risk >= 0.4:
        reasons.append("Some infrastructure threat indicators")
    else:
        reasons.append("No significant infrastructure threat indicators")
    
    if risk_level == RiskLevel.HIGH:
        reasons.append("HIGH risk level: immediate attention recommended")
    elif risk_level == RiskLevel.MEDIUM:
        reasons.append("MEDIUM risk level: review recommended")
    else:
        reasons.append("LOW risk level: appears safe")
    
    unique_reasons = _tier_reasons(reasons)
    
    logger.info(
        "Fast URL score computed (consistent with investigate)",
        url_model_score=round(url_model_score, 3),
        content_risk=round(content_risk, 3),
        infrastructure_risk=round(infrastructure_risk, 3),
        final_score=round(final_score, 3),
        risk_level=risk_level.value,
    )
    
    return risk_level, round(confidence, 2), unique_reasons, final_score
