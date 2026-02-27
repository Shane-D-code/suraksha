"""
PhishGuard Intelligence Engine - Forensic Analysis & Findings Generation

PART 2 - Backend Intelligence Engine
PART 3 - Deterministic Risk Scoring
PART 4 - Dynamic Explanation Generator

This module:
1. Enriches forensic signals with domain intelligence
2. Generates structured FINDINGS from signals
3. Computes deterministic risk scores
4. Generates dynamic explanations
"""

import structlog
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum

from app.models.schemas import RiskLevel

logger = structlog.get_logger(__name__)


class FindingSeverity(str, Enum):
    """Finding severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingCategory(str, Enum):
    """Finding categories."""
    FORM_BEHAVIOR = "Form Behavior"
    DOMAIN_INTELLIGENCE = "Domain Intelligence"
    INFRASTRUCTURE = "Infrastructure"
    CONTENT = "Content"
    DOM_MANIPULATION = "DOM Manipulation"
    SCRIPT_ANALYSIS = "Script Analysis"
    BRAND_IMPERSONATION = "Brand Impersonation"


@dataclass
class Finding:
    """
    Structured finding from forensic signal analysis.
    
    Each finding contains:
    - severity: LOW, MEDIUM, HIGH, CRITICAL
    - category: Domain, Form, Content, etc.
    - message: Dynamic message constructed from actual signal values
    - signal_origin: Which forensic signal triggered this finding
    """
    severity: FindingSeverity
    category: FindingCategory
    message: str
    signal_origin: str
    raw_value: Any = None
    weight: float = 0.0  # For deterministic scoring
    
    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "category": self.category.value,
            "message": self.message,
            "signal_origin": self.signal_origin
        }


# Severity weights for deterministic scoring
SEVERITY_WEIGHTS = {
    FindingSeverity.LOW: 0.1,
    FindingSeverity.MEDIUM: 0.3,
    FindingSeverity.HIGH: 0.6,
    FindingSeverity.CRITICAL: 1.0,
}


class ForensicIntelligenceEngine:
    """
    Intelligence engine that:
    1. Enriches forensic signals with domain intelligence
    2. Generates structured FINDINGS
    3. Computes deterministic risk scores
    4. Generates dynamic explanations
    """
    
    def __init__(self, threat_engine=None):
        self.threat_engine = threat_engine
    
    async def analyze(self, forensic_signals: dict, domain: str) -> dict:
        """
        Main analysis entry point.
        
        Args:
            forensic_signals: Raw signals from Chrome extension
            domain: Domain being analyzed
            
        Returns:
            Complete analysis result with findings, score, and explanations
        """
        # Step 1: Enrich signals with domain intelligence
        intelligence = await self._enrich_with_intelligence(domain)
        
        # Step 2: Generate findings from signals + intelligence
        findings = self._generate_findings(forensic_signals, intelligence)
        
        # Step 3: Compute deterministic risk score
        risk_result = self._compute_risk_score(findings)
        
        # Step 4: Generate dynamic explanations
        explanations = self._generate_explanations(findings, intelligence, risk_result)
        
        # Step 5: Build final response
        return self._build_response(findings, risk_result, explanations, intelligence)
    
    async def _enrich_with_intelligence(self, domain: str) -> dict:
        """
        Enrich forensic signals with domain intelligence.
        
        Returns dict with:
        - domain_age_days
        - registrar
        - ssl_valid
        - asn_reputation
        - threat_feed_match
        - gnn_similarity
        - campaign_id
        """
        intelligence = {
            "domain_age_days": None,
            "registrar": None,
            "ssl_valid": True,
            "asn_reputation": "unknown",
            "threat_feed_match": False,
            "gnn_similarity": 0.0,
            "campaign_id": None,
            "is_malicious": False,
            "registrant_country": None,
        }
        
        if not self.threat_engine:
            logger.warning("No threat engine available for enrichment")
            return intelligence
        
        try:
            # Get domain intelligence from threat engine
            result = await self.threat_engine.analyze(domain)
            
            intelligence["domain_age_days"] = result.domain_age_days
            intelligence["registrar"] = result.registrar
            intelligence["ssl_valid"] = result.ssl_valid
            intelligence["asn_reputation"] = result.asn if result.asn else "unknown"
            intelligence["campaign_id"] = result.campaign_id
            intelligence["gnn_similarity"] = result.gnn_score
            intelligence["is_malicious"] = result.known_malicious
            intelligence["registrant_country"] = result.registrant_country
            
            # Check for threat feed match
            if result.known_malicious or result.threat_category:
                intelligence["threat_feed_match"] = True
                
        except Exception as e:
            logger.error("Intelligence enrichment failed", error=str(e))
        
        return intelligence
    
    def _generate_findings(self, signals: dict, intelligence: dict) -> List[Finding]:
        """
        Generate structured findings from forensic signals and intelligence.
        
        Each finding is dynamically constructed from actual signal values.
        NO static templates - every message uses real data.
        """
        findings: List[Finding] = []
        
        # ============================================
        # FORM BEHAVIOR FINDINGS
        # ============================================
        form = signals.get("form_analysis", {})
        
        if form.get("login_detected"):
            if form.get("external_submission"):
                submission_domain = form.get("submission_domain") or "external domain"
                findings.append(Finding(
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.FORM_BEHAVIOR,
                    message=f"Login form submits data to external domain ({submission_domain})",
                    signal_origin="form_analysis.external_submission",
                    raw_value=submission_domain,
                    weight=SEVERITY_WEIGHTS[FindingSeverity.CRITICAL]
                ))
            else:
                findings.append(Finding(
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.FORM_BEHAVIOR,
                    message="Login form detected but submits to same domain",
                    signal_origin="form_analysis.login_detected",
                    raw_value=True,
                    weight=SEVERITY_WEIGHTS[FindingSeverity.LOW]
                ))
        
        if form.get("hidden_inputs_count", 0) > 2:
            count = form.get("hidden_inputs_count")
            findings.append(Finding(
                severity=FindingSeverity.HIGH,
                category=FindingCategory.FORM_BEHAVIOR,
                message=f"Form contains {count} hidden input fields - common phishing technique",
                signal_origin="form_analysis.hidden_inputs_count",
                raw_value=count,
                weight=SEVERITY_WEIGHTS[FindingSeverity.HIGH]
            ))
        
        if form.get("password_in_iframe"):
            findings.append(Finding(
                severity=FindingSeverity.CRITICAL,
                category=FindingCategory.FORM_BEHAVIOR,
                message="Password field detected inside iframe - credential harvesting attempt",
                signal_origin="form_analysis.password_in_iframe",
                raw_value=True,
                weight=SEVERITY_WEIGHTS[FindingSeverity.CRITICAL]
            ))
        
        # ============================================
        # SCRIPT ANALYSIS FINDINGS
        # ============================================
        scripts = signals.get("script_analysis", {})
        
        ext_script_count = scripts.get("external_script_count", 0)
        if ext_script_count > 5:
            findings.append(Finding(
                severity=FindingSeverity.HIGH,
                category=FindingCategory.SCRIPT_ANALYSIS,
                message=f"Page loads {ext_script_count} external scripts - potential data exfiltration risk",
                signal_origin="script_analysis.external_script_count",
                raw_value=ext_script_count,
                weight=SEVERITY_WEIGHTS[FindingSeverity.HIGH]
            ))
        
        suspicious_domains = scripts.get("suspicious_script_domains", [])
        if suspicious_domains:
            findings.append(Finding(
                severity=FindingSeverity.CRITICAL,
                category=FindingCategory.SCRIPT_ANALYSIS,
                message=f"Page loads scripts from suspicious domains: {', '.join(suspicious_domains[:3])}",
                signal_origin="script_analysis.suspicious_script_domains",
                raw_value=suspicious_domains,
                weight=SEVERITY_WEIGHTS[FindingSeverity.CRITICAL]
            ))
        
        # ============================================
        # DOM MANIPULATION FINDINGS
        # ============================================
        dom = signals.get("dom_manipulation", {})
        
        if dom.get("right_click_disabled"):
            findings.append(Finding(
                severity=FindingSeverity.HIGH,
                category=FindingCategory.DOM_MANIPULATION,
                message="Right-click context menu disabled - prevents users from viewing page source",
                signal_origin="dom_manipulation.right_click_disabled",
                raw_value=True,
                weight=SEVERITY_WEIGHTS[FindingSeverity.HIGH]
            ))
        
        if dom.get("iframe_count", 0) > 1:
            count = dom.get("iframe_count")
            findings.append(Finding(
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.DOM_MANIPULATION,
                message=f"Page contains {count} iframe elements - could be hiding malicious content",
                signal_origin="dom_manipulation.iframe_count",
                raw_value=count,
                weight=SEVERITY_WEIGHTS[FindingSeverity.MEDIUM]
            ))
        
        # ============================================
        # CONTENT & BRAND FINDINGS
        # ============================================
        content = signals.get("content_analysis", {})
        
        brand = content.get("brand_detected")
        if brand:
            findings.append(Finding(
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.BRAND_IMPERSONATION,
                message=f"Page appears to impersonate brand: {brand}",
                signal_origin="content_analysis.brand_detected",
                raw_value=brand,
                weight=SEVERITY_WEIGHTS[FindingSeverity.MEDIUM]
            ))
        
        urgency = content.get("urgency_score", 0.0)
        if urgency > 0.7:
            findings.append(Finding(
                severity=FindingSeverity.HIGH,
                category=FindingCategory.CONTENT,
                message=f"Page contains high urgency language (score: {urgency:.2f}) - social engineering attempt",
                signal_origin="content_analysis.urgency_score",
                raw_value=urgency,
                weight=SEVERITY_WEIGHTS[FindingSeverity.HIGH]
            ))
        
        # ============================================
        # DOMAIN INTELLIGENCE FINDINGS
        # ============================================
        
        if intelligence.get("is_malicious") or intelligence.get("threat_feed_match"):
            findings.append(Finding(
                severity=FindingSeverity.CRITICAL,
                category=FindingCategory.DOMAIN_INTELLIGENCE,
                message="Domain is flagged in threat intelligence feeds as malicious",
                signal_origin="intelligence.threat_feed_match",
                raw_value=True,
                weight=SEVERITY_WEIGHTS[FindingSeverity.CRITICAL]
            ))
        
        age_days = intelligence.get("domain_age_days")
        if age_days is not None:
            if age_days < 7:
                findings.append(Finding(
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.DOMAIN_INTELLIGENCE,
                    message=f"Domain is only {age_days} days old - recently registered for phishing",
                    signal_origin="intelligence.domain_age_days",
                    raw_value=age_days,
                    weight=SEVERITY_WEIGHTS[FindingSeverity.HIGH]
                ))
            elif age_days < 30:
                findings.append(Finding(
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.DOMAIN_INTELLIGENCE,
                    message=f"Domain is {age_days} days old - relatively new registration",
                    signal_origin="intelligence.domain_age_days",
                    raw_value=age_days,
                    weight=SEVERITY_WEIGHTS[FindingSeverity.MEDIUM]
                ))
        
        if not intelligence.get("ssl_valid", True):
            findings.append(Finding(
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.INFRASTRUCTURE,
                message="Domain has invalid or missing SSL certificate",
                signal_origin="intelligence.ssl_valid",
                raw_value=False,
                weight=SEVERITY_WEIGHTS[FindingSeverity.MEDIUM]
            ))
        
        campaign_id = intelligence.get("campaign_id")
        if campaign_id:
            findings.append(Finding(
                severity=FindingSeverity.CRITICAL,
                category=FindingCategory.INFRASTRUCTURE,
                message=f"Domain is part of active phishing campaign: {campaign_id}",
                signal_origin="intelligence.campaign_id",
                raw_value=campaign_id,
                weight=SEVERITY_WEIGHTS[FindingSeverity.CRITICAL]
            ))
        
        gnn_sim = intelligence.get("gnn_similarity", 0.0)
        if gnn_sim > 0.8:
            findings.append(Finding(
                severity=FindingSeverity.HIGH,
                category=FindingCategory.INFRASTRUCTURE,
                message=f"Domain infrastructure has {gnn_sim:.0%} similarity to known phishing domains",
                signal_origin="intelligence.gnn_similarity",
                raw_value=gnn_sim,
                weight=SEVERITY_WEIGHTS[FindingSeverity.HIGH]
            ))
        
        # Sort findings by severity (most critical first)
        severity_order = {FindingSeverity.CRITICAL: 0, FindingSeverity.HIGH: 1, 
                         FindingSeverity.MEDIUM: 2, FindingSeverity.LOW: 3}
        findings.sort(key=lambda f: severity_order[f.severity])
        
        return findings
    
    def _compute_risk_score(self, findings: List[Finding]) -> dict:
        """
        Deterministic risk scoring through mathematical aggregation.
        
        Algorithm:
        1. Sum weighted findings
        2. Apply normalization factor
        3. Clamp to [0, 1]
        4. Classify into LOW/MEDIUM/HIGH
        """
        if not findings:
            return {
                "score": 0.0,
                "confidence": 1.0,
                "risk_level": RiskLevel.LOW,
                "finding_count": 0
            }
        
        # Sum weighted findings
        total_weight = sum(f.weight for f in findings)
        
        # Normalize by count to prevent unbounded growth
        # More findings = higher confidence in the score
        count = len(findings)
        normalized_score = total_weight / (1 + 0.1 * count)
        
        # Clamp to [0, 1]
        final_score = min(max(normalized_score, 0.0), 1.0)
        
        # Determine risk level with CRITICAL threshold
        if final_score >= 0.9:
            risk_level = RiskLevel.CRITICAL
        elif final_score >= 0.7:
            risk_level = RiskLevel.HIGH
        elif final_score >= 0.4:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        # Confidence: higher when more findings, lower when borderline
        # Use entropy-like calculation
        confidence = min(0.95, 0.5 + (0.05 * count))
        
        # Adjust confidence based on score distance from threshold
        if 0.35 < final_score < 0.45 or 0.65 < final_score < 0.75:
            confidence *= 0.8  # Borderline region - lower confidence
        
        return {
            "score": round(final_score, 3),
            "confidence": round(confidence, 2),
            "risk_level": risk_level,
            "finding_count": count,
            "critical_count": sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL),
            "high_count": sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
        }
    
    def _generate_explanations(self, findings: List[Finding], intelligence: dict, risk_result: dict) -> dict:
        """
        Generate dynamic explanations from actual findings.
        
        - Summary: Human-readable paragraph
        - Bullet points: Key findings
        - Advanced: Technical breakdown
        """
        if not findings:
            return {
                "summary": "No suspicious indicators detected. This page appears safe based on forensic analysis.",
                "bullet_points": ["No form behavior anomalies detected", "No domain intelligence threats identified"],
                "technical": {}
            }
        
        # Group findings by category
        categories_present = set(f.category for f in findings)
        
        # Build summary paragraph dynamically
        summary_parts = []
        
        # Critical findings first
        critical_findings = [f for f in findings if f.severity == FindingSeverity.CRITICAL]
        if critical_findings:
            summary_parts.append(f"This page contains {len(critical_findings)} critical threat indicator(s).")
        
        # High findings
        high_findings = [f for f in findings if f.severity == FindingSeverity.HIGH]
        if high_findings:
            summary_parts.append(f"Analysis detected {len(high_findings)} high-severity security concern(s).")
        
        # Medium findings
        medium_findings = [f for f in findings if f.severity == FindingSeverity.MEDIUM]
        if medium_findings:
            summary_parts.append(f"{len(medium_findings)} medium-severity warning(s) were identified.")
        
        # Add category context
        if FindingCategory.FORM_BEHAVIOR in categories_present:
            summary_parts.append("Form behavior analysis reveals suspicious submission patterns.")
        if FindingCategory.DOMAIN_INTELLIGENCE in categories_present:
            summary_parts.append("Domain intelligence indicates potential threat.")
        if FindingCategory.BRAND_IMPERSONATION in categories_present:
            summary_parts.append("Brand impersonation detected.")
        
        summary = " ".join(summary_parts)
        
        # Build bullet points from findings
        bullet_points = [f.message for f in findings[:10]]  # Limit to top 10
        
        # Build technical breakdown
        technical = {
            "domain_age_days": intelligence.get("domain_age_days"),
            "registrar": intelligence.get("registrar"),
            "ssl_valid": intelligence.get("ssl_valid"),
            "gnn_similarity": intelligence.get("gnn_similarity"),
            "campaign_id": intelligence.get("campaign_id"),
            "threat_feed_match": intelligence.get("threat_feed_match"),
            "finding_breakdown": {
                "critical": risk_result.get("critical_count", 0),
                "high": risk_result.get("high_count", 0),
                "medium": len(medium_findings),
                "low": len([f for f in findings if f.severity == FindingSeverity.LOW])
            }
        }
        
        return {
            "summary": summary,
            "bullet_points": bullet_points,
            "technical": technical
        }
    
    def _build_response(self, findings: List[Finding], risk_result: dict, 
                       explanations: dict, intelligence: dict) -> dict:
        """Build final API response in required format."""
        
        return {
            "risk": risk_result["risk_level"].value,
            "confidence": risk_result["confidence"],
            "summary": explanations["summary"],
            "findings": [f.to_dict() for f in findings],
            "advanced": {
                "domain_age_days": intelligence.get("domain_age_days"),
                "gnn_similarity": intelligence.get("gnn_similarity"),
                "campaign_id": intelligence.get("campaign_id"),
                "registrar": intelligence.get("registrar"),
                "ssl_valid": intelligence.get("ssl_valid"),
                "threat_feed_match": intelligence.get("threat_feed_match"),
                "finding_breakdown": explanations["technical"].get("finding_breakdown", {}),
                "bullet_points": explanations["bullet_points"]
            }
        }


# Module-level engine instance
_engine: Optional[ForensicIntelligenceEngine] = None


def get_forensic_engine(threat_engine=None) -> ForensicIntelligenceEngine:
    """Get or create forensic intelligence engine instance."""
    global _engine
    if _engine is None:
        _engine = ForensicIntelligenceEngine(threat_engine)
    return _engine
