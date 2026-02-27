"""
PhishGuard Integrated API Server
Combines:
- Original HTTPServer API (scan, feedback, status, GNN)
- Dashboard Routes (JWT auth, live threats, campaigns, graph, endpoints, trends, investigate)
- WebSocket for real-time updates
"""

import logging
import os
import sys
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import jwt
import hashlib

# Add paths for ML modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'threat_intel'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'ml'))

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

# ============================================
# FASTAPI APP SETUP
# ============================================

app = FastAPI(
    title="PhishGuard API",
    description="Enterprise Phishing Detection & SOC Dashboard",
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

# ============================================
# GNN & THREAT INTEL INITIALIZATION
# ============================================

gnn_engine = None
if GNN_AVAILABLE:
    try:
        gnn_engine = get_inference_engine(
            model_path='ml/models/gnn_model.pt',
            data_dir='ml/data'
        )
        logger.info("GNN Inference Engine initialized")
    except Exception as e:
        logger.error(f"Failed to initialize GNN engine: {e}")
        gnn_engine = None

threat_scheduler = None
if THREAT_INTEL_AVAILABLE:
    try:
        threat_scheduler = ThreatIntelligenceScheduler(
            db_path='threat_intel.db',
            sync_interval_minutes=30
        )
        threat_scheduler.add_feed(CustomFeed('threat_feeds/custom_threats.txt'))
        logger.info("Threat intelligence initialized")
    except Exception as e:
        logger.error(f"Failed to initialize threat intelligence: {e}")
        threat_scheduler = None

# ============================================
# AUTHENTICATION SETUP
# ============================================

SECRET_KEY = os.environ.get("DASHBOARD_SECRET", "phishguard-secret-key-change-in-production")
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Mock users database
USERS_DB = {
    "admin": {
        "username": "admin",
        "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
        "role": "admin",
        "full_name": "Security Admin"
    },
    "analyst": {
        "username": "analyst",
        "password_hash": hashlib.sha256("analyst123".encode()).hexdigest(),
        "role": "analyst",
        "full_name": "SOC Analyst"
    },
    "viewer": {
        "username": "viewer",
        "password_hash": hashlib.sha256("viewer123".encode()).hexdigest(),
        "role": "viewer",
        "full_name": "Read-Only Viewer"
    }
}

token_blacklist = set()


# ============================================
# AUTH MODELS
# ============================================

class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict


class User(BaseModel):
    username: str
    role: str
    full_name: str


class ThreatEvent(BaseModel):
    id: str
    domain: str
    risk_score: float
    confidence: float
    detection_source: str
    timestamp: str
    campaign_id: Optional[str] = None


class CampaignInfo(BaseModel):
    campaign_id: str
    cluster_size: int
    domains: list
    shared_ip: Optional[str] = None
    shared_cert: Optional[str] = None
    first_seen: str
    avg_risk_score: float
    growth_trend: str


class EndpointStats(BaseModel):
    total_endpoints: int
    scans_per_minute: float
    blocked_attempts: int
    override_rate: float
    offline_detections: int
    last_update: str


class RiskTrend(BaseModel):
    date: str
    blocked_count: int
    zero_day_count: int
    new_campaigns: int


class InvestigationData(BaseModel):
    domain: str
    risk_score: float
    nlp_explanation: str
    dom_indicators: list
    infra_gnn_score: float
    campaign_id: Optional[str]
    domain_age_days: int
    whois_summary: dict
    related_domains: list


# ============================================
# AUTH ENDPOINTS
# ============================================

@app.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login endpoint - returns JWT token"""
    
    user = USERS_DB.get(form_data.username)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    password_hash = hashlib.sha256(form_data.password.encode()).hexdigest()
    
    if password_hash != user["password_hash"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token_data = {
        "sub": user["username"],
        "role": user["role"],
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    
    access_token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "username": user["username"],
            "role": user["role"],
            "full_name": user["full_name"]
        }
    }


@app.post("/auth/logout")
async def logout(token: str = Depends(oauth2_scheme)):
    """Logout - blacklist current token"""
    token_blacklist.add(token)
    return {"message": "Successfully logged out"}


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Dependency to get current authenticated user"""
    
    if token in token_blacklist:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been invalidated"
        )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        user = USERS_DB.get(username)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        return {
            "username": user["username"],
            "role": user["role"],
            "full_name": user["full_name"]
        }
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


def require_role(required_role: str):
    """Dependency factory for role-based access"""
    async def role_checker(user: dict = Depends(get_current_user)):
        role_hierarchy = {"admin": 3, "analyst": 2, "viewer": 1}
        
        if role_hierarchy.get(user["role"], 0) < role_hierarchy.get(required_role, 0):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' or higher required"
            )
        return user
    
    return role_checker


# ============================================
# DASHBOARD ENDPOINTS
# ============================================

@app.get("/dashboard/live-threats", response_model=list[ThreatEvent])
async def get_live_threats(
    limit: int = 20,
    current_user: dict = Depends(get_current_user)
):
    """Get live threat feed - latest blocked domains"""
    
    mock_threats = [
        {
            "id": "evt_001",
            "domain": "secure-login-verify.xyz",
            "risk_score": 0.92,
            "confidence": 0.88,
            "detection_source": "GNN",
            "timestamp": datetime.utcnow().isoformat(),
            "campaign_id": "campaign_1"
        },
        {
            "id": "evt_002",
            "domain": "paypal-verify-account.ml",
            "risk_score": 0.89,
            "confidence": 0.85,
            "detection_source": "NLP",
            "timestamp": datetime.utcnow().isoformat(),
            "campaign_id": "campaign_2"
        },
        {
            "id": "evt_003",
            "domain": "amazon-order-confirm.tk",
            "risk_score": 0.78,
            "confidence": 0.72,
            "detection_source": "DOM",
            "timestamp": datetime.utcnow().isoformat(),
            "campaign_id": None
        }
    ]
    
    return mock_threats[:limit]


@app.get("/dashboard/campaigns", response_model=list[CampaignInfo])
async def get_campaigns(
    current_user: dict = Depends(get_current_user)
):
    """Get all detected phishing campaigns"""
    
    mock_campaigns = [
        {
            "campaign_id": "campaign_1",
            "cluster_size": 12,
            "domains": [
                "secure-login-verify.xyz",
                "account-verify-login.xyz",
                "verify-secure-login.xyz"
            ],
            "shared_ip": "192.168.1.100",
            "shared_cert": "abc123def456",
            "first_seen": "2024-01-15T10:00:00Z",
            "avg_risk_score": 0.91,
            "growth_trend": "growing"
        },
        {
            "campaign_id": "campaign_2",
            "cluster_size": 8,
            "domains": [
                "paypal-verify-account.ml",
                "paypal-confirm.ml",
                "paypal-security.ml"
            ],
            "shared_ip": "10.0.0.50",
            "shared_cert": "cert_xyz789",
            "first_seen": "2024-01-10T08:30:00Z",
            "avg_risk_score": 0.87,
            "growth_trend": "stable"
        }
    ]
    
    return mock_campaigns


@app.get("/dashboard/graph")
async def get_infrastructure_graph(
    current_user: dict = Depends(get_current_user)
):
    """Get infrastructure graph for visualization"""
    
    return {
        "nodes": [
            {"id": "domain_1", "label": "secure-login-verify.xyz", "type": "domain", "risk": 0.92},
            {"id": "domain_2", "label": "account-verify-login.xyz", "type": "domain", "risk": 0.89},
            {"id": "ip_1", "label": "192.168.1.100", "type": "ip", "risk": 0.85},
            {"id": "cert_1", "label": "*.xyz SSL", "type": "certificate", "risk": 0.78},
            {"id": "domain_3", "label": "legitimate-site.com", "type": "domain", "risk": 0.1},
            {"id": "ip_2", "label": "8.8.8.8", "type": "ip", "risk": 0.05}
        ],
        "edges": [
            {"source": "domain_1", "target": "ip_1", "type": "hosts_on"},
            {"source": "domain_2", "target": "ip_1", "type": "hosts_on"},
            {"source": "domain_1", "target": "cert_1", "type": "uses_cert"},
            {"source": "domain_3", "target": "ip_2", "type": "hosts_on"}
        ]
    }


@app.get("/dashboard/endpoint-stats", response_model=EndpointStats)
async def get_endpoint_stats(
    current_user: dict = Depends(get_current_user)
):
    """Get endpoint activity metrics"""
    
    return {
        "total_endpoints": 1247,
        "scans_per_minute": 45.3,
        "blocked_attempts": 8934,
        "override_rate": 0.023,
        "offline_detections": 156,
        "last_update": datetime.utcnow().isoformat()
    }


@app.get("/dashboard/risk-trends", response_model=list[RiskTrend])
async def get_risk_trends(
    days: int = 7,
    current_user: dict = Depends(get_current_user)
):
    """Get risk trend analytics"""
    
    trends = []
    for i in range(days):
        date = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        trends.append({
            "date": date,
            "blocked_count": 120 + i * 10,
            "zero_day_count": 5 + i,
            "new_campaigns": 1 + (i % 3)
        })
    
    return list(reversed(trends))


@app.get("/dashboard/investigate/{domain}", response_model=InvestigationData)
async def investigate_domain(
    domain: str,
    current_user: dict = Depends(get_current_user)
):
    """Get detailed investigation data for a domain"""
    
    return {
        "domain": domain,
        "risk_score": 0.92,
        "nlp_explanation": "Contains social engineering keywords: 'verify', 'secure', 'login'. Urgency language detected.",
        "dom_indicators": [
            "Password input field detected",
            "Multiple hidden form fields",
            "External iframe present",
            "Form action points to suspicious endpoint"
        ],
        "infra_gnn_score": 0.87,
        "campaign_id": "campaign_1",
        "domain_age_days": 3,
        "whois_summary": {
            "registrar": "NameCheap",
            "registrant": "REDACTED",
            "created_date": "2024-01-12",
            "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"]
        },
        "related_domains": [
            {"domain": "account-verify-login.xyz", "relation": "shared_ip", "risk": 0.89},
            {"domain": "verify-secure-login.xyz", "relation": "shared_cert", "risk": 0.85}
        ]
    }


@app.get("/dashboard/summary")
async def get_dashboard_summary(
    current_user: dict = Depends(get_current_user)
):
    """Get quick dashboard summary for overview panel"""
    
    return {
        "total_threats_blocked_today": 342,
        "active_campaigns": 5,
        "zero_day_detections": 12,
        "endpoints_protected": 1247,
        "average_risk_score": 0.73,
        "top_targeted_brands": [
            {"brand": "PayPal", "attempts": 234},
            {"brand": "Amazon", "attempts": 189},
            {"brand": "Microsoft", "attempts": 156},
            {"brand": "Apple", "attempts": 123},
            {"brand": "Google", "attempts": 98}
        ],
        "recent_activity": [
            {"time": "2 min ago", "event": "Campaign #3 detected", "severity": "high"},
            {"time": "5 min ago", "event": "Zero-day blocked", "severity": "critical"},
            {"time": "12 min ago", "event": "New endpoint registered", "severity": "low"}
        ]
    }


# ============================================
# ADMIN ENDPOINTS
# ============================================

@app.get("/admin/users")
async def list_users(
    current_user: dict = Depends(require_role("admin"))
):
    """List all users (admin only)"""
    
    return [
        {"username": "admin", "role": "admin", "full_name": "Security Admin"},
        {"username": "analyst", "role": "analyst", "full_name": "SOC Analyst"},
        {"username": "viewer", "role": "viewer", "full_name": "Read-Only Viewer"}
    ]


@app.post("/admin/users")
async def create_user(
    username: str,
    password: str,
    role: str,
    full_name: str,
    current_user: dict = Depends(require_role("admin"))
):
    """Create new user (admin only)"""
    
    if username in USERS_DB:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    USERS_DB[username] = {
        "username": username,
        "password_hash": hashlib.sha256(password.encode()).hexdigest(),
        "role": role,
        "full_name": full_name
    }
    
    return {"message": f"User {username} created successfully"}


# ============================================
# WEBSOCKET FOR REAL-TIME UPDATES
# ============================================

class ConnectionManager:
    """WebSocket connection manager for real-time dashboard updates"""
    
    def __init__(self):
        self.active_connections: list[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        await websocket.send_json(message)
    
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass


manager = ConnectionManager()


@app.websocket("/ws/dashboard")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time dashboard updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Send periodic heartbeat
            update = {
                "type": "heartbeat",
                "timestamp": datetime.utcnow().isoformat(),
                "active_connections": len(manager.active_connections)
            }
            await websocket.send_json(update)
            
            # Wait 5 seconds between updates
            import asyncio
            await asyncio.sleep(5)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


async def broadcast_to_dashboards(message: dict):
    """Broadcast message to all connected dashboard clients"""
    await manager.broadcast(message)


# ============================================
# ORIGINAL API ENDPOINTS (ported from HTTPServer)
# ============================================

class ScanRequest(BaseModel):
    url: str
    suspicious_keywords_found: list = []
    long_url: bool = False
    excessive_subdomains: bool = False
    subdomain_count: int = 0
    suspicious_url_keywords: bool = False
    password_fields: int = 0
    external_links: int = 0
    hidden_inputs: int = 0
    iframe_count: int = 0
    local_result: Optional[dict] = None


@app.post("/scan")
async def scan_page(request: ScanRequest):
    """Analyze page/email/message for phishing indicators"""
    
    domain = request.url
    if not domain.startswith('http'):
        domain = f'http://{domain}'
    from urllib.parse import urlparse
    domain = urlparse(domain).netloc or urlparse(domain).path
    
    logger.info(f"Scanning: {domain}")
    
    # Calculate risk score
    risk_result = calculate_risk(request.dict(), domain)
    
    logger.info(f"Result: {risk_result['risk']} ({risk_result['confidence']})")
    
    return risk_result


@app.post("/feedback")
async def submit_feedback(data: dict):
    """Log user feedback"""
    logger.info(f"Feedback received: {data.get('type', 'unknown')}")
    return {"success": True}


@app.get("/status")
async def get_status():
    """Get server status"""
    return {
        "server": "PhishGuard API",
        "version": "7.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "threat_intelligence": "enabled" if threat_scheduler else "disabled",
        "gnn_inference": "enabled" if (GNN_AVAILABLE and gnn_engine) else "disabled",
        "dashboard": "enabled"
    }


@app.get("/threat-cache")
async def get_threat_cache():
    """Get threat intelligence cache"""
    cache = {
        "malicious_domains": [],
        "high_risk_patterns": [],
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if threat_scheduler:
        db_stats = threat_scheduler.db.get_statistics()
        cache["total_threats"] = db_stats.get("total_domains", 0)
    
    return cache


@app.get("/gnn/campaigns")
async def get_gnn_campaigns():
    """Get GNN-detected campaigns"""
    if gnn_engine:
        campaigns = gnn_engine.detect_campaigns()
        return {
            "success": True,
            "campaigns": campaigns,
            "count": len(campaigns)
        }
    return {"success": False, "error": "GNN not available"}


@app.get("/gnn/similar")
async def get_similar_domains(domain: str = None, k: int = 5):
    """Find similar domains using GNN"""
    if domain and gnn_engine:
        if domain in gnn_engine.node_id_map:
            idx = gnn_engine.node_id_map[domain]
            similar = gnn_engine._find_similar_domains(idx, k)
            return {
                "success": True,
                "domain": domain,
                "similar_domains": similar
            }
        return {"success": False, "error": "Domain not in graph"}
    return {"success": False, "error": "GNN not available or missing domain"}


@app.get("/gnn/status")
async def get_gnn_status():
    """Get GNN inference status"""
    if gnn_engine:
        return {
            "success": True,
            "status": gnn_engine.get_status()
        }
    return {"success": False, "error": "GNN not available"}


# ============================================
# RISK CALCULATION LOGIC
# ============================================

def calculate_risk(data: dict, domain: str) -> dict:
    """Calculate comprehensive risk score with GNN integration"""
    
    score = 0.0
    reasons = []
    
    gnn_result = {
        "gnn_score": 0.0,
        "cluster_probability": 0.0,
        "campaign_id": None,
        "is_zero_day": False,
        "gnn_available": GNN_AVAILABLE and gnn_engine is not None
    }
    
    db = None
    if threat_scheduler:
        db = threat_scheduler.db
    
    # 1. GNN Infrastructure Analysis
    if gnn_engine:
        try:
            gnn_result = gnn_engine.check_domain(domain, db)
            
            gnn_score = gnn_result.get("gnn_score", 0.0)
            cluster_prob = gnn_result.get("cluster_probability", 0.0)
            
            if gnn_score > 0.5:
                score += gnn_score * 0.35
                reasons.append(f"GNN detected infrastructure risk: {gnn_score:.2f}")
            
            if cluster_prob > 0.5:
                score += cluster_prob * 0.15
                reasons.append(f"Part of malicious cluster (prob: {cluster_prob:.2f})")
            
            if gnn_result.get("is_zero_day"):
                zero_day = gnn_result.get("zero_day_details", {})
                for indicator in zero_day.get("threat_indicators", []):
                    reasons.append(f"Zero-day: {indicator['type']} with {indicator['count']} malicious domains")
        
        except Exception as e:
            logger.error(f"GNN inference error: {e}")
    
    # 2. Threat Intelligence
    threat_intel_score = 0.0
    if threat_scheduler and domain:
        intel_result = threat_scheduler.check_domain(domain)
        
        if intel_result.get("in_threat_db"):
            threat_intel_score = intel_result.get("risk_score", 0.0)
            reasons.append(f"Domain found in threat database (risk: {threat_intel_score:.2f})")
            score += threat_intel_score * 0.2
        else:
            infra_risk = intel_result.get("infrastructure_risk", {})
            infra_score = infra_risk.get("infrastructure_score", 0.0)
            
            if infra_score > 0.3:
                threat_intel_score = infra_score
                score += infra_score * 0.1
                
                for factor in infra_risk.get("risk_factors", []):
                    reasons.append(factor)
    
    # 3. Content-based analysis
    suspicious_keywords = data.get("suspicious_keywords_found", [])
    if suspicious_keywords:
        keyword_score = min(len(suspicious_keywords) * 0.15, 0.3)
        score += keyword_score
        reasons.append(f"Found suspicious keywords: {', '.join(suspicious_keywords[:3])}")
    
    # 4. URL-based analysis
    if data.get("long_url"):
        score += 0.1
        reasons.append("URL is unusually long")
    
    if data.get("excessive_subdomains"):
        score += 0.08
        reasons.append(f"Excessive subdomains: {data.get('subdomain_count', 0)}")
    
    if data.get("suspicious_url_keywords"):
        score += 0.07
        reasons.append("Suspicious keywords in URL")
    
    # 5. DOM-based analysis
    if data.get("password_fields", 0) > 0:
        score += 0.1
        reasons.append("Page contains password input fields")
    
    if data.get("external_links", 0) > 5:
        score += 0.1
        reasons.append(f"High number of external links: {data.get('external_links')}")
    
    if data.get("hidden_inputs", 0) > 2:
        score += 0.08
        reasons.append(f"Multiple hidden inputs: {data.get('hidden_inputs')}")
    
    if data.get("iframe_count", 0) > 0:
        score += 0.06
        reasons.append(f"Page contains {data.get('iframe_count')} iframe(s)")
    
    # 6. Local AI result
    if data.get("local_result"):
        local_risk = data["local_result"].get("local_risk", "LOW")
        local_conf = data["local_result"].get("local_confidence", 0.0)
        
        if local_risk == "HIGH":
            score += 0.2
        elif local_risk == "MEDIUM":
            score += 0.1
    
    # Normalize score
    score = min(score, 1.0)
    
    # Determine risk level
    if score >= 0.7:
        risk = "HIGH"
        confidence = score
    elif score >= 0.4:
        risk = "MEDIUM"
        confidence = score
    else:
        risk = "LOW"
        confidence = 1 - score
    
    return {
        "risk": risk,
        "confidence": round(confidence, 2),
        "reasons": reasons[:10],
        "threat_intel_score": round(threat_intel_score, 2) if threat_intel_score else 0.0,
        "total_score": round(score, 2),
        "infra_gnn_score": round(gnn_result.get("gnn_score", 0.0), 2),
        "cluster_probability": round(gnn_result.get("cluster_probability", 0.0), 2),
        "campaign_id": gnn_result.get("campaign_id"),
        "is_zero_day": gnn_result.get("is_zero_day", False),
        "gnn_enabled": gnn_result.get("gnn_available", False)
    }


# ============================================
# MAIN ENTRY POINT
# ============================================

if __name__ == "__main__":
    import uvicorn
    
    logger.info("🛡️  PhishGuard Integrated API Server")
    logger.info(f"   Version: 7.0.0 (Phase 7 - SOC Dashboard)")
    logger.info(f"   Running on http://localhost:8000")
    logger.info(f"   Threat Intelligence: {'Enabled' if threat_scheduler else 'Disabled'}")
    logger.info(f"   GNN Inference: {'Enabled' if (GNN_AVAILABLE and gnn_engine) else 'Disabled'}")
    logger.info(f"   Dashboard: Enabled")
    logger.info("")
    logger.info("API Endpoints:")
    logger.info("  POST /scan - Analyze page/email/message")
    logger.info("  POST /feedback - Log user feedback")
    logger.info("  GET /status - Server status")
    logger.info("  GET /threat-cache - Threat intelligence cache")
    logger.info("  GET /gnn/campaigns - GNN-detected campaigns")
    logger.info("  GET /gnn/similar - Find similar domains")
    logger.info("  GET /gnn/status - GNN status")
    logger.info("")
    logger.info("Dashboard Endpoints (require JWT auth):")
    logger.info("  POST /auth/login - Login")
    logger.info("  GET /dashboard/summary - Dashboard overview")
    logger.info("  GET /dashboard/live-threats - Live threat feed")
    logger.info("  GET /dashboard/campaigns - Campaign intelligence")
    logger.info("  GET /dashboard/graph - Infrastructure graph")
    logger.info("  GET /dashboard/endpoint-stats - Endpoint statistics")
    logger.info("  GET /dashboard/risk-trends - Risk trends")
    logger.info("  GET /dashboard/investigate/{domain} - Investigation")
    logger.info("  WS /ws/dashboard - Real-time updates")
    logger.info("")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)

