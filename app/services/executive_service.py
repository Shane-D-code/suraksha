"""
Executive fraud dashboard aggregation service.

Queries the scans and compliance_alerts tables to build an
executive-level fraud overview: total scans by risk, fraud counts,
trend data, recent activity, and real compliance alert counts.
"""
import structlog
from datetime import datetime, timedelta

from app.models.executive import (
    ExecutiveDashboardResponse,
    RiskDistribution,
    TrendPoint,
    RecentScanEntry,
)
from app.services.database import get_db_session

logger = structlog.get_logger(__name__)

REGULATION_MAP = {
    "RBI KYC Guidelines": "RBI KYC",
    "Anti-Money Laundering (PMLA 2002)": "AML",
    "Digital Personal Data Protection Act 2023": "DPDP",
    "CERT-In Directions": "CERT-In",
}


async def get_executive_dashboard(
    days: int = 30,
    limit: int = 10,
) -> ExecutiveDashboardResponse:
    """
    Build the executive dashboard data from the scans and compliance_alerts tables.
    """
    dist = RiskDistribution()
    trend_map: dict[str, TrendPoint] = {}
    recent_entries: list[RecentScanEntry] = []
    total_scans = 0

    for i in range(days - 1, -1, -1):
        d = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        trend_map[d] = TrendPoint(date=d)

    try:
        async for session in get_db_session():
            from sqlalchemy import select, func
            from app.models.db import Scan as DBScan, RiskLevelEnum, ComplianceAlert

            count_stmt = select(func.count(DBScan.id))
            count_result = await session.execute(count_stmt)
            total_scans = count_result.scalar() or 0

            for risk_enum, field in [
                (RiskLevelEnum.HIGH, "high"),
                (RiskLevelEnum.MEDIUM, "medium"),
                (RiskLevelEnum.LOW, "low"),
            ]:
                stmt = select(func.count(DBScan.id)).where(DBScan.risk == risk_enum)
                result = await session.execute(stmt)
                setattr(dist, field, result.scalar() or 0)

            # Trend data per day
            for i in range(days - 1, -1, -1):
                day_start = (datetime.utcnow() - timedelta(days=i)).replace(
                    hour=0, minute=0, second=0, microsecond=0
                )
                day_end = day_start + timedelta(days=1)
                date_key = day_start.strftime("%Y-%m-%d")

                tp = trend_map.get(date_key, TrendPoint(date=date_key))

                stmt = select(func.count(DBScan.id)).where(
                    DBScan.created_at >= day_start,
                    DBScan.created_at < day_end,
                )
                result = await session.execute(stmt)
                tp.scans = result.scalar() or 0

                stmt = select(func.count(DBScan.id)).where(
                    DBScan.created_at >= day_start,
                    DBScan.created_at < day_end,
                    DBScan.risk == RiskLevelEnum.HIGH,
                )
                result = await session.execute(stmt)
                tp.fraud = result.scalar() or 0

                # Real compliance count from compliance_alerts table
                comp_stmt = select(func.count(ComplianceAlert.id)).where(
                    ComplianceAlert.created_at >= day_start,
                    ComplianceAlert.created_at < day_end,
                )
                comp_result = await session.execute(comp_stmt)
                tp.compliance = comp_result.scalar() or 0

                trend_map[date_key] = tp

            # Recent scans with per-scan compliance flags
            stmt = (
                select(DBScan)
                .order_by(DBScan.created_at.desc())
                .limit(limit)
            )
            result = await session.execute(stmt)
            recent_scans = result.scalars().all()

            for s in recent_scans:
                compliance_flags = []
                if s.scan_id:
                    ca_stmt = select(ComplianceAlert.regulation).where(
                        ComplianceAlert.scan_id == s.scan_id
                    )
                    ca_result = await session.execute(ca_stmt)
                    for row in ca_result:
                        short_name = REGULATION_MAP.get(row[0], row[0])
                        if short_name not in compliance_flags:
                            compliance_flags.append(short_name)

                fraud_type = ""
                reasons = s.reasons or []
                if s.risk == RiskLevelEnum.HIGH:
                    for r in reasons:
                        rl = r.lower()
                        if "phishing" in rl or "brand" in rl:
                            fraud_type = "Phishing"
                            break
                        if "campaign" in rl:
                            fraud_type = "Campaign"
                            break
                        if "malicious" in rl or "blacklist" in rl:
                            fraud_type = "Known Malicious"
                            break
                    if not fraud_type:
                        fraud_type = "High Risk"

                source = s.url or (s.text[:80] + "..." if s.text else "N/A")
                if s.url and "//" in s.url:
                    try:
                        source = s.url.split("/")[2]
                    except IndexError:
                        source = s.url

                recent_entries.append(RecentScanEntry(
                    scan_id=s.scan_id[:12] if s.scan_id else "",
                    source=source[:60],
                    risk=s.risk.value if hasattr(s.risk, "value") else str(s.risk),
                    timestamp=s.created_at.isoformat() if s.created_at else None,
                    fraud_type=fraud_type,
                    compliance_flags=compliance_flags,
                ))

            break
    except Exception as e:
        logger.warning("Executive dashboard query failed, returning empty", error=str(e))

    compliance_alert_count = sum(tp.compliance for tp in trend_map.values())

    return ExecutiveDashboardResponse(
        total_documents_scanned=total_scans,
        fraud_detected=dist.high,
        high_risk=dist.high,
        medium_risk=dist.medium,
        low_risk=dist.low,
        compliance_alerts=compliance_alert_count,
        risk_distribution=dist,
        trend_analysis=sorted(trend_map.values(), key=lambda x: x.date),
        recent_scans=recent_entries,
    )
