"""
Report Generator — exports investigation data as PDF, CSV, JSON.
Uses ReportLab for PDF generation.
"""
import io
import csv
import json
import structlog
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

logger = structlog.get_logger(__name__)

BRAND_PRIMARY = HexColor("#06b6d4")
BRAND_DARK = HexColor("#020617")
SEVERITY_COLORS = {
    "CRITICAL": HexColor("#ef4444"),
    "HIGH": HexColor("#f59e0b"),
    "MEDIUM": HexColor("#3b82f6"),
    "LOW": HexColor("#10b981"),
}


def generate_pdf(data: dict) -> bytes:
    """Generate a professional PDF report from investigation data."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm,
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        "Title2", parent=styles["Heading1"],
        fontSize=20, textColor=BRAND_DARK, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "SubTitle", parent=styles["Normal"],
        fontSize=10, textColor=HexColor("#6b7280"), spaceAfter=12,
    ))
    styles.add(ParagraphStyle(
        "SectionHead", parent=styles["Heading2"],
        fontSize=13, textColor=BRAND_PRIMARY, spaceBefore=16, spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        "BodySmall", parent=styles["Normal"],
        fontSize=9, leading=13, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        "BodySmallBold", parent=styles["BodySmall"],
        fontName="Helvetica-Bold",
    ))

    elements = []

    # ── Header ──
    elements.append(Paragraph("PHISHGUARD NEXUS", styles["Title2"]))
    elements.append(Paragraph("Fraud Intelligence — Investigation Report", styles["SubTitle"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=BRAND_PRIMARY))
    elements.append(Spacer(1, 6*mm))

    # Meta
    meta_lines = [
        f"<b>Document:</b> {data.get('filename', 'Unknown')}",
        f"<b>Scan ID:</b> {data.get('scan_id', '—')}",
        f"<b>Report Generated:</b> {datetime.utcnow().strftime('%d %b %Y %H:%M UTC')}",
        f"<b>Uploaded:</b> {_fmt_date(data.get('timestamp'))}",
        f"<b>Status:</b> {data.get('status', 'Open')}",
        f"<b>Assigned To:</b> {data.get('assigned_to', 'Unassigned')}",
    ]
    for line in meta_lines:
        elements.append(Paragraph(line, styles["BodySmall"]))
    elements.append(Spacer(1, 4*mm))

    # ── Executive Summary ──
    elements.append(Paragraph("EXECUTIVE SUMMARY", styles["SectionHead"]))
    risk_score = data.get("risk_score", 0)
    decision = data.get("decision", "Pending")
    decision_color = SEVERITY_COLORS.get("CRITICAL" if decision == "Reject" else "HIGH" if decision == "Manual Review" else "LOW")

    summary_data = [
        ["Risk Score", f"{risk_score}/100"],
        ["Severity", data.get("risk", "—")],
        ["Recommended Decision", f'<font color="{decision_color.hexval()}">{decision}</font>'],
        ["Total Findings", str(len(data.get("findings", [])))],
        ["Compliance Alerts", str(len(data.get("compliance_alerts", [])))],
        ["Top Finding", (data.get("top_findings") or ["—"])[0] if data.get("top_findings") else "—"],
    ]
    t = Table(summary_data, colWidths=[120, 300])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), HexColor("#f3f4f6")),
        ("TEXTCOLOR", (0, 0), (-1, -1), black),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e5e7eb")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 4*mm))

    # Decision reasons
    reasons = data.get("decision_reasons", [])
    if reasons:
        elements.append(Paragraph("<b>Decision Basis:</b>", styles["BodySmallBold"]))
        for r in reasons:
            elements.append(Paragraph(f"• {r}", styles["BodySmall"]))
        elements.append(Spacer(1, 3*mm))

    # ── Risk Breakdown ──
    categories = data.get("risk_categories", [])
    if categories:
        elements.append(Paragraph("RISK BREAKDOWN", styles["SectionHead"]))
        cat_data = [["Category", "Score", "Confidence", "Findings", "Weight"]]
        for rc in categories:
            cat_data.append([
                rc.get("label", rc.get("key", "—")),
                f'{rc.get("score", 0):.1f}',
                f'{rc.get("confidence", 0) * 100:.0f}%',
                str(rc.get("findings_count", 0)),
                f'{rc.get("weight", 0) * 100:.0f}%',
            ])
        cat_data.append(["TOTAL", str(risk_score), "", "", "100%"])
        t2 = Table(cat_data, colWidths=[150, 70, 70, 70, 70])
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e5e7eb")),
            ("BACKGROUND", (0, -1), (-1, -1), HexColor("#f3f4f6")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(t2)
        elements.append(Spacer(1, 4*mm))

    # ── Key Findings ──
    findings = data.get("findings", [])
    if findings:
        elements.append(Paragraph("KEY FINDINGS", styles["SectionHead"]))
        for i, f in enumerate(findings[:10]):
            sev = f.get("severity", "MEDIUM")
            sev_color = SEVERITY_COLORS.get(sev, HexColor("#6b7280"))
            elements.append(Paragraph(
                f'<font color="{sev_color.hexval()}">■</font> '
                f'<b>{f.get("finding", "")[:200]}</b>',
                styles["BodySmall"],
            ))
            meta_parts = []
            if f.get("category"):
                meta_parts.append(f"Category: {f['category']}")
            if f.get("confidence"):
                meta_parts.append(f"Confidence: {f['confidence']*100:.0f}%")
            if f.get("score_contribution"):
                meta_parts.append(f"Contribution: +{f['score_contribution']:.1f}")
            if meta_parts:
                elements.append(Paragraph(
                    f'<font color="#6b7280">{" | ".join(meta_parts)}</font>',
                    styles["BodySmall"],
                ))

            # Evidence snippets
            evidence = f.get("evidence", [])
            for e in evidence[:2]:
                snippet = e.get("snippet", "")[:120]
                if snippet:
                    elements.append(Paragraph(
                        f'&nbsp;&nbsp;&nbsp;🔍 <font color="#3b82f6">{snippet}</font>',
                        styles["BodySmall"],
                    ))
            elements.append(Spacer(1, 2*mm))

    # ── Compliance Alerts ──
    alerts = data.get("compliance_alerts", [])
    if alerts:
        elements.append(PageBreak())
        elements.append(Paragraph("COMPLIANCE ALERTS", styles["SectionHead"]))
        for a in alerts[:8]:
            sev_color = SEVERITY_COLORS.get(a.get("compliance_severity", "MEDIUM"), HexColor("#6b7280"))
            elements.append(Paragraph(
                f'<font color="{sev_color.hexval()}">●</font> '
                f'<b>{a.get("regulation", "Regulation")}</b> — '
                f'{a.get("finding_description", a.get("finding_type", ""))[:200]}',
                styles["BodySmall"],
            ))
            elements.append(Paragraph(
                f'<font color="#6b7280">Reference: {a.get("reference", "—")[:60]} | '
                f'Severity: {a.get("compliance_severity", "—")} | '
                f'Action: {a.get("required_action", "—")[:80]}</font>',
                styles["BodySmall"],
            ))
            elements.append(Spacer(1, 2*mm))

    # ── Audit Trail ──
    audit = data.get("audit_trail", [])
    if audit:
        elements.append(Spacer(1, 4*mm))
        elements.append(Paragraph("AUDIT TRAIL", styles["SectionHead"]))
        for a_entry in audit:
            ts = a_entry.get("timestamp", "")
            step = a_entry.get("step", "")
            status = a_entry.get("status", "")
            elements.append(Paragraph(
                f'<font color="#6b7280">▸</font> {step} — {status}'
                f'{" | " + ts[:19] if ts else ""}',
                styles["BodySmall"],
            ))

    # ── Footer ──
    elements.append(Spacer(1, 10*mm))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#d1d5db")))
    elements.append(Paragraph(
        "This report was generated automatically by PhishGuard Nexus. "
        "For verification, contact the compliance team.",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=7, textColor=HexColor("#9ca3af")),
    ))

    doc.build(elements)
    return buf.getvalue()


def generate_csv(data: dict) -> str:
    """Generate a CSV report from investigation data."""
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["PhishGuard Nexus — Investigation Report"])
    writer.writerow(["Filename", data.get("filename", "Unknown")])
    writer.writerow(["Scan ID", data.get("scan_id", "—")])
    writer.writerow(["Risk Score", f'{data.get("risk_score", 0)}/100'])
    writer.writerow(["Decision", data.get("decision", "Pending")])
    writer.writerow([])
    writer.writerow(["FINDINGS"])
    writer.writerow(["ID", "Finding", "Category", "Severity", "Confidence", "Score Contribution"])
    for i, f in enumerate(data.get("findings", [])):
        writer.writerow([
            i + 1,
            f.get("finding", "")[:200],
            f.get("category", ""),
            f.get("severity", ""),
            f'{f.get("confidence", 0) * 100:.0f}%',
            f.get("score_contribution", 0),
        ])
    writer.writerow([])
    writer.writerow(["COMPLIANCE ALERTS"])
    writer.writerow(["Regulation", "Finding", "Severity", "Reference", "Action", "Timeline"])
    for a in data.get("compliance_alerts", []):
        writer.writerow([
            a.get("regulation", ""),
            a.get("finding_description", a.get("finding_type", "")),
            a.get("compliance_severity", ""),
            a.get("reference", ""),
            a.get("required_action", ""),
            a.get("timeline", ""),
        ])
    return output.getvalue()


def generate_json(data: dict) -> str:
    """Generate a JSON export of investigation data."""
    export = {
        "report_type": "investigation",
        "generated_at": datetime.utcnow().isoformat(),
        "scan_id": data.get("scan_id"),
        "filename": data.get("filename"),
        "risk_score": data.get("risk_score"),
        "risk_level": data.get("risk"),
        "decision": data.get("decision"),
        "decision_reasons": data.get("decision_reasons", []),
        "status": data.get("status"),
        "assigned_to": data.get("assigned_to"),
        "findings_count": len(data.get("findings", [])),
        "compliance_alerts_count": len(data.get("compliance_alerts", [])),
        "risk_categories": data.get("risk_categories", []),
        "findings": [
            {
                "finding": f.get("finding"),
                "category": f.get("category"),
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "score_contribution": f.get("score_contribution"),
                "evidence_count": len(f.get("evidence", [])),
            }
            for f in data.get("findings", [])
        ],
        "compliance_alerts": [
            {
                "regulation": a.get("regulation"),
                "finding": a.get("finding_description", a.get("finding_type")),
                "severity": a.get("compliance_severity"),
                "reference": a.get("reference"),
                "action": a.get("required_action"),
                "timeline": a.get("timeline"),
            }
            for a in data.get("compliance_alerts", [])
        ],
        "audit_trail": data.get("audit_trail", []),
    }
    return json.dumps(export, indent=2, default=str)


def _fmt_date(ts_str):
    if not ts_str:
        return "—"
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.strftime("%d %b %Y %H:%M")
    except Exception:
        return ts_str[:19]
