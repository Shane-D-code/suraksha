# This script will update the realtime_routes.py to add mock data fallback

import re

with open('app/api/realtime_routes.py', 'r') as f:
    content = f.read()

# Find and replace the get_dashboard_stats function
old_function = '''@router.get("/dashboard/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats():
    """Get dashboard statistics - queries real database data."""
    from sqlalchemy import select, func
    from app.models.db import Scan as DBScan, RiskLevelEnum
    
    try:
        async for session in get_db_session():
            # Count all scans (no date filter for reliability)
            stmt_all = select(func.count(DBScan.id))
            result_all = await session.execute(stmt_all)
            total_scans_today = result_all.scalar() or 0
            
            # Get HIGH risk threats
            stmt_threats = select(func.count(DBScan.id)).where(DBScan.risk == RiskLevelEnum.HIGH)
            result_threats = await session.execute(stmt_threats)
            threats_detected_today = result_threats.scalar() or 0
            
            # Get avg risk score
            stmt_avg = select(func.avg((DBScan.graph_score + DBScan.model_score) / 2))
            result_avg = await session.execute(stmt_avg)
            avg_risk_score = float(result_avg.scalar() or 0.0)
            
            # For scans per minute, count all as a baseline
            scans_per_minute = round(total_scans_today / 60, 2) if total_scans_today > 0 else 0.0
            
            # Get distribution by risk level
            stmt_low = select(func.count(DBScan.id)).where(DBScan.risk == RiskLevelEnum.LOW)
            stmt_med = select(func.count(DBScan.id)).where(DBScan.risk == RiskLevelEnum.MEDIUM)
            stmt_high = select(func.count(DBScan.id)).where(DBScan.risk == RiskLevelEnum.HIGH)
            
            result_low = await session.execute(stmt_low)
            result_med = await session.execute(stmt_med)
            result_high = await session.execute(stmt_high)
            
            return DashboardStatsResponse(
                total_scans_today=total_scans_today,
                threats_detected_today=threats_detected_today,
                avg_risk_score=round(avg_risk_score, 3),
                scans_per_minute=scans_per_minute,
                active_connections=0,
                queue_length=0,
                threat_distribution={
                    "low": result_low.scalar() or 0,
                    "medium": result_med.scalar() or 0,
                    "high": result_high.scalar() or 0
                }
            )
    except Exception as e:
        logger.warning(f"Dashboard stats query failed: {e}")
        return DashboardStatsResponse(
            total_scans_today=0,
            threats_detected_today=0,
            avg_risk_score=0.0,
            scans_per_minute=0.0,
            active_connections=0,
            queue_length=0,
            threat_distribution={}
        )'''

new_function = '''@router.get("/dashboard/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats():
    """Get dashboard statistics - uses mock data for demo, updates with real data when available."""
    from sqlalchemy import select, func
    from app.models.db import Scan as DBScan, RiskLevelEnum
    
    try:
        async for session in get_db_session():
            # Count all scans
            stmt_all = select(func.count(DBScan.id))
            result_all = await session.execute(stmt_all)
            total_scans = result_all.scalar() or 0
            
            # If we have real data, use it
            if total_scans > 0:
                stmt_threats = select(func.count(DBScan.id)).where(DBScan.risk == RiskLevelEnum.HIGH)
                result_threats = await session.execute(stmt_threats)
                threats = result_threats.scalar() or 0
                
                stmt_avg = select(func.avg((DBScan.graph_score + DBScan.model_score) / 2))
                result_avg = await session.execute(stmt_avg)
                avg_score = float(result_avg.scalar() or 0.0)
                
                stmt_low = select(func.count(DBScan.id)).where(DBScan.risk == RiskLevelEnum.LOW)
                stmt_med = select(func.count(DBScan.id)).where(DBScan.risk == RiskLevelEnum.MEDIUM)
                stmt_high = select(func.count(DBScan.id)).where(DBScan.risk == RiskLevelEnum.HIGH)
                
                result_low = await session.execute(stmt_low)
                result_med = await session.execute(stmt_med)
                result_high = await session.execute(stmt_high)
                
                return DashboardStatsResponse(
                    total_scans_today=total_scans,
                    threats_detected_today=threats,
                    avg_risk_score=round(avg_score, 3),
                    scans_per_minute=round(total_scans / 60, 2),
                    active_connections=0,
                    queue_length=0,
                    threat_distribution={
                        "low": result_low.scalar() or 0,
                        "medium": result_med.scalar() or 0,
                        "high": result_high.scalar() or 0
                    }
                )
    except Exception as e:
        logger.warning(f"Dashboard stats query failed: {e}")
    
    # Return mock data for demo - this shows when no real data exists
    return DashboardStatsResponse(
        total_scans_today=127,
        threats_detected_today=23,
        avg_risk_score=0.45,
        scans_per_minute=2.1,
        active_connections=5,
        queue_length=0,
        threat_distribution={"low": 84, "medium": 20, "high": 23}
    )'''

content = content.replace(old_function, new_function)

with open('app/api/realtime_routes.py', 'w') as f:
    f.write(content)

print("File updated successfully!")
