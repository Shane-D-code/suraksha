"""
Compliance Operations Dashboard Service

Aggregates compliance alerts from the database, derives finding status
from investigation case data, and returns a live operational dashboard.
"""
import structlog
from datetime import datetime, timedelta
from collections import defaultdict

from app.models.compliance_dashboard import (
    ComplianceDashboardResponse,
    ComplianceFindingEntry,
    FrameworkCount,
    ComplianceAnalytics,
    ComplianceChartData,
)
from app.services.database import get_db_session

logger = structlog.get_logger(__name__)

REGULATION_MAP = {
    "RBI KYC Guidelines": "RBI_KYC",
    "Anti-Money Laundering (PMLA 2002)": "AML",
    "Digital Personal Data Protection Act 2023": "DPDP",
    "CERT-In Directions": "CERT_IN",
}

REVERSE_REGULATION_MAP = {v: k for k, v in REGULATION_MAP.items()}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _derive_status(case_meta: dict) -> str:
    """Derive compliance finding status from investigation case metadata."""
    case_status = (case_meta or {}).get("status", "Open")
    human_decision = (case_meta or {}).get("human_decision")

    if case_status == "Closed":
        if human_decision == "APPROVED":
            return "RESOLVED"
        elif human_decision == "REJECTED":
            return "FALSE_POSITIVE"
        return "CLOSED"
    if case_status in ("Under Review", "Escalated") or human_decision == "MANUAL_REVIEW":
        return "UNDER_REVIEW"
    return "OPEN"


async def get_compliance_dashboard(days: int = 30) -> ComplianceDashboardResponse:
    """Build the full compliance operations dashboard from the database."""
    now = datetime.utcnow()
    cutoff = now - timedelta(days=days)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    try:
        async for session in get_db_session():
            from sqlalchemy import select, func
            from app.models.db import ComplianceAlert, Scan as DBScan

            # Fetch all compliance alerts within window + their scans
            stmt = (
                select(ComplianceAlert, DBScan)
                .join(DBScan, ComplianceAlert.scan_id == DBScan.scan_id, isouter=True)
                .where(ComplianceAlert.created_at >= cutoff)
                .order_by(ComplianceAlert.created_at.desc())
            )
            result = await session.execute(stmt)
            rows = result.all()

            if not rows:
                return ComplianceDashboardResponse(
                    updated_at=now.isoformat()
                )

            # Aggregate
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            framework_counts: dict[str, int] = {"RBI_KYC": 0, "AML": 0, "DPDP": 0, "CERT_IN": 0}
            status_counts = {"OPEN": 0, "UNDER_REVIEW": 0, "RESOLVED": 0, "FALSE_POSITIVE": 0, "CLOSED": 0}
            recent_findings: list[ComplianceFindingEntry] = []
            today_resolved = 0
            today_closed = 0
            resolution_times: list[float] = []
            daily_trend_map: dict[str, dict] = {}

            # Build daily trend map for the window
            for i in range(days - 1, -1, -1):
                d = (now - timedelta(days=i)).strftime("%Y-%m-%d")
                daily_trend_map[d] = {"date": d, "total": 0, "critical": 0, "high": 0, "resolved": 0}

            seen_docs: set = set()

            for alert, scan in rows:
                severity = alert.compliance_severity or "LOW"
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

                reg_key = REGULATION_MAP.get(alert.regulation, "OTHER")
                framework_counts[reg_key] = framework_counts.get(reg_key, 0) + 1

                case_meta = (scan.meta or {}).get("case", {}) if scan else {}
                status = _derive_status(case_meta)
                status_counts[status] = status_counts.get(status, 0) + 1

                created_date = alert.created_at.strftime("%Y-%m-%d") if alert.created_at else ""
                if created_date in daily_trend_map:
                    daily_trend_map[created_date]["total"] += 1
                    if severity in ("CRITICAL",):
                        daily_trend_map[created_date]["critical"] += 1
                    if severity in ("HIGH", "CRITICAL"):
                        daily_trend_map[created_date]["high"] += 1
                    if status == "RESOLVED":
                        daily_trend_map[created_date]["resolved"] += 1

                if status == "RESOLVED" and alert.created_at and alert.created_at >= today_start:
                    today_resolved += 1
                    # Calculate resolution time
                    review_completed_at = case_meta.get("review_completed_at")
                    if review_completed_at and alert.created_at:
                        try:
                            resolved_dt = datetime.fromisoformat(review_completed_at)
                            delta = (resolved_dt - alert.created_at).total_seconds() / 3600
                            if delta >= 0:
                                resolution_times.append(delta)
                        except (ValueError, TypeError):
                            pass

                if case_meta.get("status") == "Closed":
                    updated_at_str = case_meta.get("updated_at", "")
                    if updated_at_str:
                        try:
                            updated_dt = datetime.fromisoformat(updated_at_str)
                            if updated_dt >= today_start:
                                today_closed += 1
                        except (ValueError, TypeError):
                            pass
                    elif alert.created_at and alert.created_at >= today_start:
                        today_closed += 1

                filename = ""
                if scan:
                    meta = scan.meta or {}
                    filename = meta.get("filename", "") or (scan.url or "").replace("document://", "") or scan.scan_id[:12]

                dedup_key = f"{alert.id}:{alert.scan_id}"
                if dedup_key not in seen_docs:
                    seen_docs.add(dedup_key)
                    recent_findings.append(ComplianceFindingEntry(
                        id=alert.id,
                        scan_id=alert.scan_id or "",
                        document_name=filename[:60],
                        regulation=alert.regulation,
                        reference=alert.reference,
                        finding_type=alert.finding_type,
                        finding_description=alert.finding_description or "",
                        risk_impact=alert.risk_impact,
                        required_action=alert.required_action,
                        compliance_severity=severity,
                        status=status,
                        assigned_to=case_meta.get("assigned_to", ""),
                        analyst_decision=case_meta.get("human_decision"),
                        created_at=alert.created_at.isoformat() if alert.created_at else None,
                        updated_at=case_meta.get("updated_at"),
                        resolved_at=case_meta.get("review_completed_at") if status == "RESOLVED" else None,
                    ))

            # Sort findings newest first
            recent_findings.sort(key=lambda f: f.created_at or "", reverse=True)

            # Build analytics
            findings_by_framework = [
                FrameworkCount(label=k.replace("_", " "), key=k, count=v)
                for k, v in sorted(framework_counts.items(), key=lambda x: -x[1])
            ]

            findings_by_severity = [
                FrameworkCount(label=k, key=k.lower(), count=v)
                for k, v in sorted(severity_counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99))
            ]

            daily_trend = sorted(daily_trend_map.values(), key=lambda x: x["date"])

            open_count = status_counts.get("OPEN", 0)
            under_review_count = status_counts.get("UNDER_REVIEW", 0)
            resolved_count = status_counts.get("RESOLVED", 0)
            false_positive_count = status_counts.get("FALSE_POSITIVE", 0)
            closed_count = status_counts.get("CLOSED", 0)

            open_vs_closed = ComplianceChartData(
                labels=["Open", "Under Review", "Resolved", "False Positive", "Closed"],
                values=[open_count, under_review_count, resolved_count, false_positive_count, closed_count],
            )

            # Highest priority framework
            highest_priority_framework = None
            for fw in findings_by_framework:
                if fw.count > 0:
                    highest_priority_framework = fw.label
                    break

            # Avg resolution time
            avg_resolution_hours = round(sum(resolution_times) / len(resolution_times), 1) if resolution_times else None

            # De-duplicate findings for the list (already done above)
            # Limit to latest 50
            recent_findings = recent_findings[:50]

            return ComplianceDashboardResponse(
                total_alerts=len(rows),
                critical=severity_counts.get("CRITICAL", 0),
                high=severity_counts.get("HIGH", 0),
                medium=severity_counts.get("MEDIUM", 0),
                low=severity_counts.get("LOW", 0),
                open_findings=open_count,
                under_review=under_review_count,
                resolved_today=today_resolved,
                avg_resolution_hours=avg_resolution_hours,
                highest_priority_framework=highest_priority_framework,
                frameworks=[
                    FrameworkCount(label="RBI KYC", key="RBI_KYC", count=framework_counts.get("RBI_KYC", 0)),
                    FrameworkCount(label="AML", key="AML", count=framework_counts.get("AML", 0)),
                    FrameworkCount(label="DPDP", key="DPDP", count=framework_counts.get("DPDP", 0)),
                    FrameworkCount(label="CERT-In", key="CERT_IN", count=framework_counts.get("CERT_IN", 0)),
                ],
                recent_findings=recent_findings,
                pending_reviews=under_review_count,
                closed_today=today_closed,
                analytics=ComplianceAnalytics(
                    findings_by_framework=findings_by_framework,
                    findings_by_severity=findings_by_severity,
                    daily_trend=daily_trend,
                    open_vs_closed=open_vs_closed,
                    resolution_times=[{"hours": avg_resolution_hours}] if avg_resolution_hours else [],
                ),
                updated_at=now.isoformat(),
            )

    except Exception as e:
        logger.error("Compliance dashboard query failed", error=str(e))
        return ComplianceDashboardResponse(
            updated_at=datetime.utcnow().isoformat(),
        )
