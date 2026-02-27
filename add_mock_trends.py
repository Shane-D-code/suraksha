# Add mock data to trends and admin overrides

with open('app/api/routes.py', 'r') as f:
    content = f.read()

# Replace the risk-trends function to always return mock data
old_trends = '''@router.get("/dashboard/risk-trends")
async def get_risk_trends(
    days: int = Query(default=7, ge=1, le=30)
):
    """Get risk trend data - uses real data if available, otherwise mock data"""
    from datetime import datetime, timedelta
    
    # Try to get real data from database
    try:
        async for session in get_db_session():
            from sqlalchemy import select, func
            from app.models.db import Scan as DBScan, RiskLevelEnum
            
            trends = []
            for i in range(days):
                date = datetime.utcnow() - timedelta(days=i)
                day_start = date.replace(hour=0, minute=0, second=0, microsecond=0)
                day_end = day_start + timedelta(days=1)
                
                stmt_blocked = select(func.count(DBScan.id)).where(
                    DBScan.created_at >= day_start,
                    DBScan.created_at < day_end,
                    DBScan.risk == RiskLevelEnum.HIGH
                )
                result_blocked = await session.execute(stmt_blocked)
                blocked_count = result_blocked.scalar() or 0
                
                stmt_avg = select(func.avg((DBScan.graph_score + DBScan.model_score) / 2)).where(
                    DBScan.created_at >= day_start, DBScan.created_at < day_end
                )
                result_avg = await session.execute(stmt_avg)
                avg_risk = result_avg.scalar() or 0.5
                
                stmt_new = select(func.count(DBScan.id)).where(
                    DBScan.created_at >= day_start, DBScan.created_at < day_end, DBScan.graph_score > 0.7
                )
                result_new = await session.execute(stmt_new)
                zero_day_count = result_new.scalar() or 0
                
                stmt_campaigns = select(func.count(func.distinct(DBScan.url))).where(
                    DBScan.created_at >= day_start, DBScan.created_at < day_end, DBScan.risk == RiskLevelEnum.HIGH
                )
                result_campaigns = await session.execute(stmt_campaigns)
                new_campaigns = min(result_campaigns.scalar() or 0, 10)
                
                trends.append({
                    "date": date.strftime("%Y-%m-%d"),
                    "blocked_count": blocked_count,
                    "zero_day_count": zero_day_count,
                    "new_campaigns": new_campaigns,
                    "avg_risk_score": round(avg_risk, 2)
                })
            
            if trends and any(t['blocked_count'] > 0 or t['zero_day_count'] > 0 for t in trends):
                return list(reversed(trends))
    except Exception as e:
        logger.warning(f"Risk trends query failed: {e}")
    
    # Return mock data for demo
    trends = []
    for i in range(days):
        date = datetime.utcnow() - timedelta(days=i)
        trends.append({
            "date": date.strftime("%Y-%m-%d"),
            "blocked_count": 15 + (i % 5) * 3,
            "zero_day_count": 3 + (i % 3),
            "new_campaigns": 2 + (i % 4),
            "avg_risk_score": 0.35 + (i % 10) * 0.05
        })
    return list(reversed(trends))'''

new_trends = '''@router.get("/dashboard/risk-trends")
async def get_risk_trends(
    days: int = Query(default=7, ge=1, le=30)
):
    """Get risk trend data - returns mock demo data"""
    from datetime import datetime, timedelta
    
    # Return comprehensive mock data for demo visualization
    trends = []
    for i in range(days):
        date = datetime.utcnow() - timedelta(days=days - 1 - i)
        trends.append({
            "date": date.strftime("%Y-%m-%d"),
            "blocked_count": 42 + (i * 7) + (i % 3) * 5,
            "zero_day_count": 8 + (i * 2) + (i % 2) * 3,
            "new_campaigns": 5 + (i * 1) + (i % 4),
            "avg_risk_score": round(0.42 + (i * 0.08) + (i % 5) * 0.03, 2)
        })
    return trends'''

content = content.replace(old_trends, new_trends)

# Also update endpoint-stats to always return mock data
old_endpoints = '''@router.get("/dashboard/endpoint-stats")
async def get_endpoint_stats():
    """Get endpoint activity metrics - uses real data if available, otherwise mock data"""
    from datetime import datetime, timedelta
    
    # Try to get real data
    try:
        async for session in get_db_session():
            from sqlalchemy import select, func
            from app.models.db import Scan as DBScan, RiskLevelEnum
            
            now = datetime.utcnow()
            hour_ago = now - timedelta(hours=1)
            day_ago = now - timedelta(days=1)
            
            stmt_hour = select(func.count(DBScan.id)).where(DBScan.created_at >= hour_ago)
            result_hour = await session.execute(stmt_hour)
            scans_last_hour = result_hour.scalar() or 0
            
            scans_per_minute = round(scans_last_hour / 60, 1) if scans_last_hour > 0 else 0.0
            
            stmt_today = select(func.count(DBScan.id)).where(DBScan.created_at >= day_ago)
            result_today = await session.execute(stmt_today)
            scans_today = result_today.scalar() or 0
            
            stmt_blocked = select(func.count(DBScan.id)).where(
                DBScan.created_at >= day_ago,
                DBScan.risk == RiskLevelEnum.HIGH
            )
            result_blocked = await session.execute(stmt_blocked)
            blocked = result_blocked.scalar() or 0
            
            stmt_total = select(func.count(func.distinct(DBScan.url)))
            result_total = await session.execute(stmt_total)
            total_endpoints = result_total.scalar() or 0
            
            if total_endpoints > 0:
                return {
                    "total_endpoints": total_endpoints + 1000,
                    "scans_per_minute": scans_per_minute,
                    "blocked_attempts": blocked,
                    "override_rate": 0.023,
                    "offline_detections": 0,
                    "last_update": now.isoformat()
                }
    except Exception as e:
        logger.warning(f"Endpoint stats query failed: {e}")
    
    # Return mock data for demo
    return {
        "total_endpoints": 2847,
        "scans_per_minute": 2.3,
        "blocked_attempts": 156,
        "override_rate": 0.023,
        "offline_detections": 0,
        "last_update": datetime.utcnow().isoformat()
    }'''

new_endpoints = '''@router.get("/dashboard/endpoint-stats")
async def get_endpoint_stats():
    """Get endpoint activity metrics - returns mock demo data"""
    from datetime import datetime
    
    # Return comprehensive mock data for demo
    return {
        "total_endpoints": 4823,
        "scans_per_minute": 3.7,
        "blocked_attempts": 287,
        "override_rate": 0.031,
        "offline_detections": 12,
        "last_update": datetime.utcnow().isoformat()
    }'''

content = content.replace(old_endpoints, new_endpoints)

# Also update the admin overrides to return mock data
old_admin_overrides = '''@router.get("/admin/overrides", response_model=List[OverrideResponse])
async def list_overrides(
    current_user: dict = Depends(get_current_user),
):
    """
    List all enterprise overrides.
    
    Requires admin role.
    """
    # Check admin role
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required"
        )
    
    try:
        async for session in get_db_session():
            from sqlalchemy import select
            
            stmt = select(EnterpriseOverride).order_by(EnterpriseOverride.created_at.desc())
            result = await session.execute(stmt)
            overrides = result.scalars().all()
            
            return [
                OverrideResponse(
                    id=o.id,
                    domain=o.domain,
                    action=o.action.value,
                    reason=o.reason,
                    created_by=o.created_by,
                    expires_at=o.expires_at,
                    created_at=o.created_at,
                )
                for o in overrides
            ]
    except Exception as e:
        logger.error("Failed to list overrides", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve overrides"
        )'''

new_admin_overrides = '''@router.get("/admin/overrides", response_model=List[OverrideResponse])
async def list_overrides(
    current_user: dict = Depends(get_current_user),
):
    """
    List all enterprise overrides.
    
    Requires admin role.
    """
    # Check admin role
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required"
        )
    
    # Return mock override data for demo
    now = datetime.utcnow()
    return [
        OverrideResponse(
            id="ov-001",
            domain="trusted-partner.com",
            action="ALLOW",
            reason="Verified business partner",
            created_by="admin",
            expires_at=None,
            created_at=now - timedelta(days=5),
        ),
        OverrideResponse(
            id="ov-002",
            domain="internal-test.local",
            action="ALLOW",
            reason="Internal testing domain",
            created_by="admin",
            expires_at=now + timedelta(days=30),
            created_at=now - timedelta(days=2),
        ),
        OverrideResponse(
            id="ov-003",
            domain="known-phishing-2024.xyz",
            action="BLOCK",
            reason="Confirmed malicious domain",
            created_by="admin",
            expires_at=None,
            created_at=now - timedelta(days=1),
        ),
    ]'''

content = content.replace(old_admin_overrides, new_admin_overrides)

# Need to add timedelta import for the overrides
content = content.replace(
    'from datetime import datetime, timedelta',
    'from datetime import datetime, timedelta'
)

with open('app/api/routes.py', 'w') as f:
    f.write(content)

print("Mock data added to trends, endpoint-stats, and admin overrides!")
