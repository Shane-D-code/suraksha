"""
PhishGuard Integrated FastAPI Server
Combines threat intelligence API + SOC Dashboard routes
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List
import logging
import sys
import os
from datetime import datetime

# Add paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'threat_intel'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'ml'))

# Import dashboard routes
from dashboard_routes import router as dashboard_router

# Try to import GNN modules
try:
    from gnn_inference import GNNInferenceEngine, get_inference_engine
    GNN_AVAILABLE = True
except ImportError as e:
    GNN_AVAILABLE = False
    logging.warning(f"GNN modules not available: {e}")

try:
    from scheduler import ThreatIntelligenceScheduler
    from feeds import CustomFeed
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False
    logging.warning("Threat intelligence modules not available")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="PhishGuard API",
    description="Enterprise Phishing Detection & Threat Intelligence Platform",
    version="7.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize GNN inference engine
gnn_engine = None
if GNN_AVAILABLE:
    try:
        gnn_engine = get_inference_engine(
            model_path='ml/models/gnn_model.pt',
            data_dir='ml/data'
        )
        logger.info("✓ GNN Inference Engine initialized")
    except Exception as e:
        logger.error(f"Failed to initialize GNN engine: {e}")
        gnn_engine = None

# Initialize threat intelligence
threat_scheduler = None
if THREAT_INTEL_AVAILABLE:
    try:
        threat_scheduler = ThreatIntelligenceScheduler(
            db_path='threat_intel.db',
            sync_interval_minutes=30
        )
        threat_scheduler.add_feed(CustomFeed('threat_feeds/custom_threats.txt'))
        logger.info("✓ Threat intelligence initialized")
    except Exception as e:
        logger.error(f"Failed to initialize threat intelligence: {e}")
        threat_scheduler = None


# ============== MODELS ==============

class ScanRequest(BaseModel):
    url: str
    suspicious_keywords_found: Optional[List[str]] = []
    long_url: Optional[bool] = False
    excessive_subdomains: Optional[bool] = False
    suspicious_url_keywords: Optional[bool] = False
    password_fields: Optional[int] = 0
    external_links: Optional[int] = 0
    hidden_inputs: Optional[int] = 0
    iframe_count: Optional[int] = 0
    local_result: Optional[dict] = None


class ScanResponse(BaseModel):
    risk: str
    confidence: float
    reasons: List[str]
    threat_intel_score: float
    total_score: float
    infra_gnn_score: float
    cluster_probability: float
    campaign_id: Optional[str]
    is_zero_day: bool
    gnn_enabled: bool


class FeedbackRequest(BaseModel):
    type: str
    url: Optional[str] = None
    details: Optional[dict] = None


# ============== CORE API ENDPOINTS ==============

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "PhishGuard API",
        "version": "7.0.0",
        "status": "online",
        "features": {
            "threat_intelligence": THREAT_INTEL_AVAILABLE,
            "gnn_inference": GNN_AVAILABLE and gnn_engine is not None,
            "soc_dashboard": True
        }
    }


@app.get("/status")
async def get_status():
    """Get server status"""
    status = {
        'server': 'PhishGuard API',
        'version': '7.0.0',
        'timestamp': datetime.now().isoformat(),
        'threat_intelligence': 'enabled' if threat_scheduler else 'disabled',
        'gnn_inference': 'enabled' if (GNN_AVAILABLE and gnn_engine) else 'disabled'
    }
    
    if threat_scheduler:
        status['threat_intel_status'] = threat_scheduler.get_status()
    
    if gnn_engine:
        status['gnn_status'] = gnn_engine.get_status()
    
    return status


@app.post("/scan", response_model=ScanResponse)
async def scan_endpoint(request: ScanRequest):
    """
    Scan URL/domain for phishing threats
    Integrates: Threat Intel + GNN + Content Analysis
    """
    try:
        # Extract domain from URL
        from urllib.parse import urlparse
        url = request.url
        if not url.startswith('http'):
            url = f'http://{url}'
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        logger.info(f"Scanning: {domain}")
        
        # Calculate risk score
        risk_result = calculate_risk(request.dict(), domain)
        
        logger.info(f"Result: {risk_result['risk']} ({risk_result['confidence']})")
        
        return risk_result
        
    except Exception as e:
        logger.error(f"Scan error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/feedback")
async def feedback_endpoint(request: FeedbackRequest):
    """Handle user feedback/reports"""
    logger.info(f"Feedback received: {request.type}")
    return {"success": True, "message": "Feedback recorded"}


@app.get("/threat-cache")
async def get_threat_cache():
    """Get threat intelligence cache"""
    cache = {
        'malicious_domains': [],
        'high_risk_patterns': [],
        'timestamp': datetime.now().isoformat()
    }
    
    if threat_scheduler:
        db_stats = threat_scheduler.db.get_statistics()
        cache['total_threats'] = db_stats.get('total_domains', 0)
    
    return cache


# ============== GNN ENDPOINTS ==============

@app.get("/gnn/status")
async def gnn_status():
    """Get GNN engine status"""
    if gnn_engine:
        return {
            'success': True,
            'status': gnn_engine.get_status()
        }
    return {'success': False, 'error': 'GNN not available'}


@app.get("/gnn/campaigns")
async def gnn_campaigns():
    """Get detected campaigns"""
    if gnn_engine:
        campaigns = gnn_engine.detect_campaigns()
        return {
            'success': True,
            'campaigns': campaigns,
            'count': len(campaigns)
        }
    return {'success': False, 'error': 'GNN not available'}


@app.get("/gnn/similar")
async def gnn_similar_domains(domain: str, k: int = 5):
    """Find similar domains"""
    if domain and gnn_engine:
        similar = gnn_engine.find_similar_domains(domain, top_k=k)
        return {
            'success': True,
            'domain': domain,
            'similar_domains': similar
        }
    return {'success': False, 'error': 'GNN not available or missing domain'}


# ============== HELPER FUNCTIONS ==============

def calculate_risk(data: dict, domain: str) -> dict:
    """Calculate comprehensive risk score with GNN integration"""
    score = 0.0
    reasons = []
    
    # GNN-based infrastructure score
    gnn_result = {
        'gnn_score': 0.0,
        'cluster_probability': 0.0,
        'campaign_id': None,
        'is_zero_day': False,
        'gnn_available': GNN_AVAILABLE and gnn_engine is not None
    }
    
    # Get database for zero-day detection
    db = None
    if threat_scheduler:
        db = threat_scheduler.db
    
    # 1. GNN Infrastructure Analysis
    if gnn_engine:
        try:
            gnn_result = gnn_engine.check_domain(domain, db)
            
            gnn_score = gnn_result.get('gnn_score', 0.0)
            cluster_prob = gnn_result.get('cluster_probability', 0.0)
            
            if gnn_score > 0.5:
                score += gnn_score * 0.35  # 35% weight for GNN
                reasons.append(f"GNN detected infrastructure risk: {gnn_score:.2f}")
            
            if cluster_prob > 0.5:
                score += cluster_prob * 0.15  # 15% weight for cluster
                reasons.append(f"Part of malicious cluster (prob: {cluster_prob:.2f})")
            
            # Zero-day detection
            if gnn_result.get('is_zero_day'):
                zero_day = gnn_result.get('zero_day_details', {})
                for indicator in zero_day.get('threat_indicators', []):
                    reasons.append(f"Zero-day: {indicator['type']} with {indicator['count']} malicious domains")
        
        except Exception as e:
            logger.error(f"GNN inference error: {e}")
    
    # 2. Threat intelligence database
    threat_intel_score = 0.0
    if threat_scheduler and domain:
        intel_result = threat_scheduler.check_domain(domain)
        
        if intel_result.get('in_threat_db'):
            threat_intel_score = intel_result.get('risk_score', 0.0)
            reasons.append(f"Domain found in threat database (risk: {threat_intel_score:.2f})")
            score += threat_intel_score * 0.2  # 20% weight
        else:
            infra_risk = intel_result.get('infrastructure_risk', {})
            infra_score = infra_risk.get('infrastructure_score', 0.0)
            
            if infra_score > 0.3:
                threat_intel_score = infra_score
                score += infra_score * 0.1  # 10% weight
                
                for factor in infra_risk.get('risk_factors', []):
                    reasons.append(factor)
    
    # 3. Content-based analysis
    suspicious_keywords = data.get('suspicious_keywords_found', [])
    if suspicious_keywords:
        keyword_score = min(len(suspicious_keywords) * 0.15, 0.3)
        score += keyword_score
        reasons.append(f"Found suspicious keywords: {', '.join(suspicious_keywords[:3])}")
    
    # 4. URL-based analysis
    if data.get('long_url'):
        score += 0.1
        reasons.append('URL is unusually long')
    
    if data.get('excessive_subdomains'):
        score += 0.08
        reasons.append(f"Excessive subdomains")
    
    if data.get('suspicious_url_keywords'):
        score += 0.07
        reasons.append('Suspicious keywords in URL')
    
    # 5. DOM-based analysis
    if data.get('password_fields', 0) > 0:
        score += 0.1
        reasons.append('Page contains password input fields')
    
    if data.get('external_links', 0) > 5:
        score += 0.1
        reasons.append(f"High number of external links: {data.get('external_links')}")
    
    if data.get('hidden_inputs', 0) > 2:
        score += 0.08
        reasons.append(f"Multiple hidden inputs: {data.get('hidden_inputs')}")
    
    if data.get('iframe_count', 0) > 0:
        score += 0.06
        reasons.append(f"Page contains {data.get('iframe_count')} iframe(s)")
    
    # 6. Local AI result
    if data.get('local_result'):
        local_risk = data['local_result'].get('local_risk', 'LOW')
        if local_risk == 'HIGH':
            score += 0.2
        elif local_risk == 'MEDIUM':
            score += 0.1
    
    # Normalize score
    score = min(score, 1.0)
    
    # Determine risk level
    if score >= 0.7:
        risk = 'HIGH'
        confidence = score
    elif score >= 0.4:
        risk = 'MEDIUM'
        confidence = score
    else:
        risk = 'LOW'
        confidence = 1 - score
    
    return {
        'risk': risk,
        'confidence': round(confidence, 2),
        'reasons': reasons[:10],
        'threat_intel_score': round(threat_intel_score, 2) if threat_intel_score else 0.0,
        'total_score': round(score, 2),
        'infra_gnn_score': round(gnn_result.get('gnn_score', 0.0), 2),
        'cluster_probability': round(gnn_result.get('cluster_probability', 0.0), 2),
        'campaign_id': gnn_result.get('campaign_id'),
        'is_zero_day': gnn_result.get('is_zero_day', False),
        'gnn_enabled': gnn_result.get('gnn_available', False)
    }


# ============== INCLUDE DASHBOARD ROUTES ==============

app.include_router(dashboard_router, tags=["dashboard"])


# ============== STARTUP/SHUTDOWN ==============

@app.on_event("startup")
async def startup_event():
    """Run on server startup"""
    logger.info("=" * 60)
    logger.info("🛡️  PhishGuard Integrated Server Starting...")
    logger.info("=" * 60)
    logger.info(f"   Version: 7.0.0 (Phase 7 - SOC Dashboard)")
    logger.info(f"   Threat Intelligence: {'✓ Enabled' if threat_scheduler else '✗ Disabled'}")
    logger.info(f"   GNN Inference: {'✓ Enabled' if gnn_engine else '✗ Disabled'}")
    logger.info(f"   SOC Dashboard: ✓ Enabled")
    logger.info("=" * 60)
    logger.info("   API Endpoints:")
    logger.info("     POST /scan - Analyze page/email/message")
    logger.info("     POST /feedback - Log user feedback")
    logger.info("     GET /status - Server status")
    logger.info("     GET /threat-cache - Threat intelligence cache")
    logger.info("     GET /gnn/* - GNN-specific endpoints")
    logger.info("")
    logger.info("   Dashboard Endpoints:")
    logger.info("     POST /auth/login - Authentication")
    logger.info("     GET /dashboard/* - Dashboard data")
    logger.info("     WS /ws/dashboard - Real-time updates")
    logger.info("=" * 60)


@app.on_event("shutdown")
async def shutdown_event():
    """Run on server shutdown"""
    logger.info("Shutting down PhishGuard server...")


# ============== MAIN ==============

if __name__ == '__main__':
    import uvicorn
    
    uvicorn.run(
        "integrated_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
