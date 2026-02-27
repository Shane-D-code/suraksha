# Dashboard API Routes
# FastAPI routes for enterprise SOC dashboard

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import jwt
import hashlib
import os

router = APIRouter()

# Secret key for JWT
SECRET_KEY = os.environ.get("DASHBOARD_SECRET", "phishguard-secret-key-change-in-production")
ALGORITHM = "HS256"

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Mock users database (in production, use real DB)
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

# Token blacklist (for logout)
token_blacklist = set()


# ============== MODELS ==============

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
    detection_source: str  # NLP, GNN, DOM, INFRA
    timestamp: str
    campaign_id: Optional[str] = None


class CampaignInfo(BaseModel):
    campaign_id: str
    cluster_size: int
    domains: List[str]
    shared_ip: Optional[str] = None
    shared_cert: Optional[str] = None
    first_seen: str
    avg_risk_score: float
    growth_trend: str  # growing, stable, declining


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
    dom_indicators: List[str]
    infra_gnn_score: float
    campaign_id: Optional[str]
    domain_age_days: int
    whois_summary: dict
    related_domains: List[dict]


# ============== AUTHENTICATION ==============

@router.post("/auth/login", response_model=Token)
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
    
    # Create JWT token
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


@router.post("/auth/logout")
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
        # Role hierarchy: admin > analyst > viewer
        role_hierarchy = {"admin": 3, "analyst": 2, "viewer": 1}
        
        if role_hierarchy.get(user["role"], 0) < role_hierarchy.get(required_role, 0):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' or higher required"
            )
        return user
    
    return role_checker


# ============== DASHBOARD ENDPOINTS ==============

@router.get("/dashboard/live-threats", response_model=List[ThreatEvent])
async def get_live_threats(
    limit: int = 20,
    current_user: dict = Depends(get_current_user)
):
    """
    Get live threat feed - latest blocked domains
    Updates every 5 seconds from real-time pipeline
    """
    
    # In production, this would pull from Redis/DB with real-time updates
    # For demo, return mock data with timestamps
    
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


@router.get("/dashboard/campaigns", response_model=List[CampaignInfo])
async def get_campaigns(
    current_user: dict = Depends(get_current_user)
):
    """
    Get all detected phishing campaigns
    Includes cluster info, shared infrastructure, growth trends
    """
    
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


@router.get("/dashboard/graph")
async def get_infrastructure_graph(
    current_user: dict = Depends(get_current_user)
):
    """
    Get infrastructure graph for visualization
    Returns nodes (Domain, IP, SSL) and edges (relationships)
    Compatible with D3.js / Cytoscape.js
    """
    
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


@router.get("/dashboard/endpoint-stats", response_model=EndpointStats)
async def get_endpoint_stats(
    current_user: dict = Depends(get_current_user)
):
    """
    Get endpoint activity metrics
    Total connected, scans/min, blocked, override rate, offline detections
    """
    
    return {
        "total_endpoints": 1247,
        "scans_per_minute": 45.3,
        "blocked_attempts": 8934,
        "override_rate": 0.023,
        "offline_detections": 156,
        "last_update": datetime.utcnow().isoformat()
    }


@router.get("/dashboard/risk-trends", response_model=List[RiskTrend])
async def get_risk_trends(
    days: int = 7,
    current_user: dict = Depends(get_current_user)
):
    """
    Get risk trend analytics
    Daily blocked attempts, zero-day detections, campaign growth
    """
    
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


@router.get("/dashboard/investigate/{domain}", response_model=InvestigationData)
async def investigate_domain(
    domain: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Get detailed investigation data for a domain
    NLP explanation, DOM indicators, GNN score, campaign, WHOIS
    """
    
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


@router.get("/dashboard/summary")
async def get_dashboard_summary(
    current_user: dict = Depends(get_current_user)
):
    """
    Get quick dashboard summary for overview panel
    """
    
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


# ============== ADMIN ENDPOINTS ==============

@router.get("/admin/users")
async def list_users(
    current_user: dict = Depends(require_role("admin"))
):
    """List all users (admin only)"""
    
    return [
        {"username": "admin", "role": "admin", "full_name": "Security Admin"},
        {"username": "analyst", "role": "analyst", "full_name": "SOC Analyst"},
        {"username": "viewer", "role": "viewer", "full_name": "Read-Only Viewer"}
    ]


@router.post("/admin/users")
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


# ============== WEBSOCKET FOR REAL-TIME ==============

from fastapi import WebSocket

active_websocket_connections = []


@router.websocket("/ws/dashboard")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket for real-time dashboard updates
    Pushes new threats, campaign updates, endpoint stats
    """
    await websocket.accept()
    active_websocket_connections.append(websocket)
    
    try:
        while True:
            # Send periodic updates
            import json
            update = {
                "type": "heartbeat",
                "timestamp": datetime.utcnow().isoformat(),
                "active_connections": len(active_websocket_connections)
            }
            await websocket.send_text(json.dumps(update))
            
            # In production, this would push real threat data
            # For demo, just send heartbeat every 5 seconds
            import asyncio
            await asyncio.sleep(5)
            
    except Exception:
        pass
    finally:
        if websocket in active_websocket_connections:
            active_websocket_connections.remove(websocket)


async def broadcast_to_dashboards(message: dict):
    """Broadcast message to all connected dashboard clients"""
    import json
    
    for websocket in active_websocket_connections:
        try:
            await websocket.send_text(json.dumps(message))
        except:
            pass

