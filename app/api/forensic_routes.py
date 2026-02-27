"""
Forensic Analysis API Routes

These endpoints handle forensic signal analysis from the Chrome Extension.
The extension sends live DOM signals which are analyzed by the forensic engine.
"""

import structlog
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.models.forensic import ForensicSignals
from app.models.schemas import RiskLevel
from app.services.forensic_engine import get_forensic_engine
from app.services.threat_graph_engine import get_threat_engine
from app.middleware.auth import get_current_user

logger = structlog.get_logger(__name__)
router = APIRouter()
security = HTTPBearer()


# ============== FORENSIC ANALYSIS ENDPOINTS ==============

@router.post("/forensic/analyze")
async def analyze_forensic_signals(
    signals: ForensicSignals,
    current_user: dict = Depends(get_current_user),
):
    """
    Analyze forensic signals from Chrome Extension.
    
    This endpoint receives live DOM analysis signals from the browser extension
    and enriches them with backend intelligence to generate findings and risk scores.
    
    Request body (ForensicSignals):
    - url_context: Current page URL and domain
    - form_analysis: Form behavior analysis (login detection, external submission)
    - script_analysis: External script analysis
    - dom_manipulation: DOM manipulation indicators
    - content_analysis: Brand detection and urgency scoring
    
    Returns:
    - risk: LOW, MEDIUM, or HIGH risk level
    - confidence: Confidence score (0-1)
    - summary: Human-readable analysis summary
    - findings: List of specific findings with severity
    - advanced: Technical details and domain intelligence
    """
    # Extract domain from URL context
    domain = signals.url_context.current_domain
    
    logger.info(
        "Forensic analysis requested",
        domain=domain,
        extension_version=signals.extension_version,
    )
    
    # Get threat engine for intelligence enrichment
    try:
        threat_engine = await get_threat_engine()
    except Exception as e:
        logger.warning(f"Threat engine not available: {e}")
        threat_engine = None
    
    # Get forensic engine and run analysis
    try:
        forensic_engine = get_forensic_engine(threat_engine=threat_engine)
        
        # Convert Pydantic model to dict for the engine
        signals_dict = signals.model_dump()
        
        # Run forensic analysis
        result = await forensic_engine.analyze(
            forensic_signals=signals_dict,
            domain=domain,
        )
        
        logger.info(
            "Forensic analysis completed",
            domain=domain,
            risk=result.get("risk"),
            confidence=result.get("confidence"),
            finding_count=len(result.get("findings", [])),
        )
        
        return result
        
    except Exception as e:
        logger.error(
            "Forensic analysis failed",
            domain=domain,
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Forensic analysis failed: {str(e)}",
        )


@router.post("/forensic/analyze-quick")
async def quick_forensic_analysis(
    url: str,
    login_detected: bool = False,
    external_submission: bool = False,
    external_domain: Optional[str] = None,
    hidden_inputs: int = 0,
    right_click_disabled: bool = False,
    urgency_score: float = 0.0,
    brand_detected: Optional[str] = None,
):
    """
    Quick forensic analysis with simplified parameters.
    
    This is a simplified endpoint for quick threat assessment without
    the full forensic signal package. Use the full /forensic/analyze
    endpoint for comprehensive analysis.
    
    Query parameters:
    - url: Page URL
    - login_detected: Whether login form was detected
    - external_submission: Whether form submits to external domain
    - external_domain: Domain form submits to (if external)
    - hidden_inputs: Count of hidden input fields
    - right_click_disabled: Whether right-click is disabled
    - urgency_score: Urgency keyword score (0-1)
    - brand_detected: Brand being impersonated (if any)
    
    Returns:
    - risk: Risk level
    - confidence: Confidence score
    - summary: Analysis summary
    """
    # Extract domain from URL
    domain = url.split("/")[2] if "//" in url else url.split("/")[0]
    
    # Build simplified signals dict
    signals = {
        "url_context": {
            "current_domain": domain,
            "page_url": url,
        },
        "form_analysis": {
            "login_detected": login_detected,
            "external_submission": external_submission,
            "submission_domain": external_domain,
            "hidden_inputs_count": hidden_inputs,
            "password_in_iframe": False,
        },
        "script_analysis": {
            "external_script_count": 0,
            "unique_script_domains": 0,
            "suspicious_script_domains": [],
        },
        "dom_manipulation": {
            "right_click_disabled": right_click_disabled,
            "obfuscated_html_detected": False,
            "iframe_count": 0,
        },
        "content_analysis": {
            "brand_detected": brand_detected,
            "urgency_score": urgency_score,
            "keyword_density": 0.0,
        },
    }
    
    # Get threat engine for intelligence
    try:
        threat_engine = await get_threat_engine()
    except Exception:
        threat_engine = None
    
    # Run analysis
    try:
        forensic_engine = get_forensic_engine(threat_engine=threat_engine)
        result = await forensic_engine.analyze(
            forensic_signals=signals,
            domain=domain,
        )
        
        return result
        
    except Exception as e:
        logger.error("Quick forensic analysis failed", error=str(e))
        # Return safe default on error
        return {
            "risk": RiskLevel.LOW.value,
            "confidence": 0.5,
            "summary": "Analysis failed - defaulting to safe",
            "findings": [],
            "advanced": {},
        }


@router.get("/forensic/domain/{domain}")
async def get_domain_forensic_context(
    domain: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Get forensic context for a domain without signals.
    
    This endpoint enriches a domain with intelligence from threat feeds,
    GNN analysis, and campaign tracking without requiring forensic signals.
    
    Path parameter:
    - domain: Domain to investigate
    
    Returns:
    - Domain intelligence including:
      - age, registrar, SSL status
      - GNN similarity score
      - Campaign participation
      - Threat feed matches
    """
    # Get threat engine
    try:
        threat_engine = await get_threat_engine()
    except Exception as e:
        logger.warning(f"Threat engine not available: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat intelligence service unavailable",
        )
    
    try:
        # Analyze domain
        result = await threat_engine.analyze(domain)
        
        return {
            "domain": domain,
            "domain_age_days": result.domain_age_days,
            "registrar": result.registrar,
            "ssl_valid": result.ssl_valid,
            "gnn_score": result.gnn_score,
            "infrastructure_risk_score": result.infrastructure_risk_score,
            "campaign_id": result.campaign_id,
            "known_malicious": result.known_malicious,
            "threat_category": result.threat_category,
            "registrant_country": result.registrant_country,
            "reasons": result.reasons,
        }
        
    except Exception as e:
        logger.error("Domain forensic context failed", domain=domain, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get domain context: {str(e)}",
        )


@router.get("/forensic/campaigns")
async def get_active_campaigns(
    current_user: dict = Depends(get_current_user),
):
    """
    Get all active phishing campaigns.
    
    Returns list of detected campaigns with:
    - campaign_id: Unique campaign identifier
    - domains: List of domains in campaign
    - first_seen: Campaign start date
    - risk_score: Campaign severity
    """
    try:
        threat_engine = await get_threat_engine()
        campaigns = await threat_engine.campaign_detector.detect_all_campaigns()
        
        return {
            "campaigns": [c.to_dict() for c in campaigns],
            "total": len(campaigns),
        }
        
    except Exception as e:
        logger.error("Failed to get campaigns", error=str(e))
        return {
            "campaigns": [],
            "total": 0,
        }


@router.get("/forensic/campaign/{campaign_id}")
async def get_campaign_details(
    campaign_id: str,
    current_user: dict = Depends(get_current_user),
):
    """
    Get details for a specific phishing campaign.
    
    Path parameter:
    - campaign_id: Campaign identifier
    
    Returns:
    - Campaign details including connected domains, IPs, certificates
    """
    try:
        threat_engine = await get_threat_engine()
        
        # Get campaign from detector
        campaign = await threat_engine.campaign_detector.get_campaign(campaign_id)
        
        if not campaign:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Campaign not found: {campaign_id}",
            )
        
        return campaign.to_dict()
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get campaign details", campaign_id=campaign_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get campaign details: {str(e)}",
        )
