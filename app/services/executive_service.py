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
    ExecutiveDecisionResponse,
    DashboardStatisticsResponse,
    AnalystDecisionRequest,
    AnalystDecisionResponse,
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


async def get_executive_decision() -> ExecutiveDecisionResponse:
    """Get the latest completed investigation's executive decision data."""
    try:
        async for session in get_db_session():
            from sqlalchemy import select, func
            from app.models.db import Scan as DBScan, ComplianceAlert

            stmt = select(DBScan).order_by(DBScan.created_at.desc()).limit(1)
            result = await session.execute(stmt)
            scan = result.scalar_one_or_none()

            if not scan:
                return ExecutiveDecisionResponse()

            meta = scan.meta or {}

            # Fraud probability from model_score (fraud_confidence / 100)
            fraud_probability = round(scan.model_score * 100, 1) if scan.model_score else 0.0

            # Risk score from risk categories weighted average
            risk_categories = meta.get("risk_categories", [])
            if risk_categories:
                total_weight = sum(rc.get("weight", 0) for rc in risk_categories)
                if total_weight > 0:
                    risk_score = round(sum(rc.get("score", 0) * rc.get("weight", 0) for rc in risk_categories) / total_weight)
                else:
                    risk_score = round(sum(rc.get("score", 0) for rc in risk_categories) / len(risk_categories))
            else:
                risk_score = int(scan.model_score * 100) if scan.model_score else 0

            # Compliance alerts for this scan
            ca_stmt = select(ComplianceAlert.compliance_severity).where(
                ComplianceAlert.scan_id == scan.scan_id
            )
            ca_result = await session.execute(ca_stmt)
            severities = [row[0] for row in ca_result]
            ca_count = len(severities)

            if ca_count == 0:
                compliance = None
            elif any(s in ("CRITICAL", "HIGH") for s in severities):
                compliance = "Severe"
            else:
                compliance = "Moderate"

            critical_count = sum(1 for s in severities if s == "CRITICAL")
            high_count = sum(1 for s in severities if s == "HIGH")
            if critical_count > 0:
                regulatory_risk = "Critical"
            elif high_count > 0:
                regulatory_risk = "High"
            elif ca_count > 0:
                regulatory_risk = "Elevated"
            else:
                regulatory_risk = None

            # Decision
            if risk_score >= 80:
                decision = "REJECT"
            elif risk_score >= 50:
                decision = "REVIEW"
            else:
                decision = "APPROVE"

            # Primary reason
            reasons = scan.reasons or []
            primary_reason = reasons[0][:200] if reasons else (
                risk_categories[0].get("label", "No significant findings") if risk_categories else "No significant findings"
            )

            # Recommendation
            recommendations = meta.get("recommendations", [])
            recommendation = recommendations[0] if recommendations else (
                "Manual verification required." if decision == "REVIEW" else
                "Document rejected — immediate escalation." if decision == "REJECT" else
                "Standard processing — no action required."
            )

            return ExecutiveDecisionResponse(
                fraud_probability=fraud_probability,
                risk_score=risk_score,
                decision=decision,
                confidence=round(scan.confidence * 100, 1) if scan.confidence else None,
                compliance=compliance,
                regulatory_risk=regulatory_risk,
                primary_reason=primary_reason,
                recommendation=recommendation,
                updated_at=scan.created_at.isoformat() if scan.created_at else None,
            )
    except Exception as e:
        logger.warning("Executive decision query failed", error=str(e))
        return ExecutiveDecisionResponse()


async def get_dashboard_statistics() -> DashboardStatisticsResponse:
    """Compute real-time dashboard statistics from the database."""
    try:
        async for session in get_db_session():
            from sqlalchemy import select, func
            from app.models.db import Scan as DBScan, RiskLevelEnum, ComplianceAlert

            # Documents Scanned — count all completed investigations
            stmt = select(func.count(DBScan.id))
            result = await session.execute(stmt)
            documents_scanned = result.scalar() or 0

            if documents_scanned == 0:
                return DashboardStatisticsResponse(
                    updated_at=datetime.utcnow().isoformat()
                )

            # Fraud Detected — count where risk_score >= fraud threshold (model_score >= 0.7)
            stmt = select(func.count(DBScan.id)).where(DBScan.model_score >= 0.7)
            result = await session.execute(stmt)
            fraud_detected = result.scalar() or 0

            # High Risk Applications — count HIGH risk scans
            stmt = select(func.count(DBScan.id)).where(DBScan.risk == RiskLevelEnum.HIGH)
            result = await session.execute(stmt)
            high_risk = result.scalar() or 0

            # Compliance Alerts — count scans having one or more compliance violations
            stmt = select(func.count(func.distinct(ComplianceAlert.scan_id)))
            result = await session.execute(stmt)
            compliance_alerts = result.scalar() or 0

            # Average Risk — average of model_score * 100 across all scans
            stmt = select(func.avg(DBScan.model_score))
            result = await session.execute(stmt)
            avg_model = result.scalar()
            average_risk = round((avg_model or 0.0) * 100, 1)

            return DashboardStatisticsResponse(
                documents_scanned=documents_scanned,
                fraud_detected=fraud_detected,
                high_risk=high_risk,
                compliance_alerts=compliance_alerts,
                average_risk=average_risk,
                updated_at=datetime.utcnow().isoformat(),
            )
    except Exception as e:
        logger.warning("Dashboard statistics query failed", error=str(e))
        return DashboardStatisticsResponse(
            updated_at=datetime.utcnow().isoformat(),
        )


async def save_analyst_decision(
    scan_id: str,
    request: AnalystDecisionRequest,
    current_user: dict,
) -> AnalystDecisionResponse:
    """Save the analyst's decision for an investigation."""
    try:
        async for session in get_db_session():
            from sqlalchemy import select
            from app.models.db import Scan as DBScan

            stmt = select(DBScan).where(DBScan.scan_id == scan_id)
            result = await session.execute(stmt)
            scan = result.scalar_one_or_none()

            if not scan:
                raise ValueError("Investigation not found")

            meta = dict(scan.meta or {})
            case_meta = dict(meta.get("case", {}))

            case_meta["human_decision"] = request.decision
            if request.reviewer_notes:
                case_meta["reviewer_notes"] = request.reviewer_notes
            if request.assigned_team:
                case_meta["assigned_team"] = request.assigned_team
            case_meta["reviewed_by"] = current_user.get("full_name") or current_user.get("username", "unknown")
            case_meta["review_completed_at"] = datetime.utcnow().isoformat()
            case_meta["review_status"] = "Completed"
            case_meta["notify_compliance"] = request.notify_compliance
            case_meta["require_branch_verification"] = request.require_branch_verification
            case_meta["escalate_manager"] = request.escalate_manager
            case_meta["freeze_processing"] = request.freeze_processing

            if request.decision in ("APPROVED", "REJECTED"):
                case_meta["status"] = "Closed"
            elif request.decision == "MANUAL_REVIEW":
                case_meta["status"] = "Under Review"

            case_meta["updated_by"] = current_user.get("username", "unknown")
            case_meta["updated_at"] = datetime.utcnow().isoformat()
            meta["case"] = case_meta

            audit_entry = {
                "step": f"Decision: {request.decision}",
                "timestamp": datetime.utcnow().isoformat(),
                "status": "completed",
                "actor": current_user.get("username", "unknown"),
                "details": {
                    "decision": request.decision,
                    "notes": request.reviewer_notes,
                    "team": request.assigned_team,
                },
            }
            audit_trail = meta.get("audit_trail", [])
            audit_trail.append(audit_entry)
            meta["audit_trail"] = audit_trail

            scan.meta = meta
            await session.commit()

            return AnalystDecisionResponse(
                scan_id=scan_id,
                decision=request.decision,
                reviewer_notes=request.reviewer_notes,
                assigned_team=request.assigned_team,
                reviewed_by=current_user.get("full_name") or current_user.get("username", "unknown"),
                review_completed_at=case_meta["review_completed_at"],
                review_status="Completed",
                notify_compliance=request.notify_compliance,
                require_branch_verification=request.require_branch_verification,
                escalate_manager=request.escalate_manager,
                freeze_processing=request.freeze_processing,
                message="Decision saved successfully",
            )
    except ValueError:
        raise
    except Exception as e:
        logger.error("Failed to save analyst decision", scan_id=scan_id, error=str(e))
        raise
