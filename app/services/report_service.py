from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from flask import current_app

from app import db
from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Incident


def report_data(report_type: str) -> dict:
    generated = datetime.now(timezone.utc).isoformat()
    if report_type == "incident":
        items = [incident.to_dict() for incident in Incident.query.order_by(Incident.created_at.desc()).limit(current_app.config["REPORT_MAX_RECORDS"])]
    elif report_type == "events":
        items = [event.to_dict() for event in Event.query.order_by(Event.timestamp.desc()).limit(current_app.config["REPORT_MAX_RECORDS"])]
    else:
        items = [alert.to_dict() for alert in Alert.query.order_by(Alert.created_at.desc()).limit(current_app.config["REPORT_MAX_RECORDS"])]
    return {"report_type": report_type, "generated_at": generated, "record_count": len(items), "items": items}


def render_report(report_type: str, format_name: str) -> tuple[bytes, str, str]:
    data = report_data(report_type)
    filename = f"cybersentinel-{report_type}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    if format_name == "json":
        return json.dumps(data, indent=2, default=str).encode("utf-8"), "application/json", f"{filename}.json"
    if format_name == "csv":
        output = io.StringIO()
        items = data["items"]
        if items:
            fields = sorted({key for item in items for key in item})
            writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows({key: json.dumps(value, default=str) if isinstance(value, (dict, list)) else value for key, value in item.items()} for item in items)
        return output.getvalue().encode("utf-8"), "text/csv", f"{filename}.csv"
    if format_name == "pdf":
        content = _render_pdf_report(data)
        return content, "application/pdf", f"{filename}.pdf"
    raise ValueError("format must be one of json, csv, or pdf")


def _render_pdf_report(data: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    output = io.BytesIO()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontSize=19, leading=23, textColor=colors.HexColor("#15345b"), alignment=TA_CENTER, spaceAfter=8))
    styles.add(ParagraphStyle(name="SectionTitle", parent=styles["Heading2"], fontSize=13, leading=16, textColor=colors.HexColor("#15345b"), spaceBefore=12, spaceAfter=7))
    styles.add(ParagraphStyle(name="ReportSmall", parent=styles["BodyText"], fontSize=8, leading=10))
    styles.add(ParagraphStyle(name="ReportCell", parent=styles["BodyText"], fontSize=8, leading=10))
    document = SimpleDocTemplate(
        output, pagesize=letter, rightMargin=0.55 * inch, leftMargin=0.55 * inch,
        topMargin=0.6 * inch, bottomMargin=0.55 * inch,
        title=f"CyberSentinel {data['report_type'].title()} Security Report",
        author="CyberSentinel AI SOC",
    )
    cell = styles["ReportCell"]

    def paragraph(value: object, style=cell) -> Paragraph:
        text = escape(str(value if value is not None else "—")).replace("\n", "<br/>")
        return Paragraph(text, style)

    def styled_table(rows: list[list], widths: list[float]) -> Table:
        result = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
        result.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8eef6")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#15345b")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#b7c4d4")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        return result

    def add_page_number(canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#66758a"))
        canvas.drawString(0.55 * inch, 0.32 * inch, "CyberSentinel AI SOC · Authorized defensive monitoring")
        canvas.drawRightString(7.95 * inch, 0.32 * inch, f"Page {doc.page}")
        canvas.restoreState()

    earliest, latest = db.session.query(db.func.min(Event.timestamp), db.func.max(Event.timestamp)).one()
    period = (
        f"{earliest.isoformat()} to {latest.isoformat()}"
        if earliest and latest else "No event timestamps in the database"
    )
    threshold = current_app.config["ML_ANOMALY_ALERT_THRESHOLD"]
    summary_rows = [
        [paragraph("Total events"), paragraph("Total alerts"), paragraph("Critical alerts"), paragraph("Incidents")],
        [
            paragraph(Event.query.count()), paragraph(Alert.query.count()),
            paragraph(Alert.query.filter_by(severity="critical").count()),
            paragraph(Incident.query.count()),
        ],
    ]
    story = [
        Paragraph("CyberSentinel AI SOC", styles["ReportTitle"]),
        Paragraph(f"{escape(data['report_type'].title())} Security Report", styles["Heading1"]),
        paragraph(f"Generated: {data['generated_at']}", styles["ReportSmall"]),
        paragraph(f"Reporting period: {period}", styles["ReportSmall"]),
        Spacer(1, 10),
        Paragraph("Executive Summary", styles["SectionTitle"]),
        styled_table(summary_rows, [1.32 * inch] * 4),
    ]

    rule_counts = Counter(
        rule_id.split("-", 1)[0]
        for (rule_id,) in db.session.query(Alert.rule_id).all()
    )
    threat_rows = [[paragraph("Threat category"), paragraph("Alert count")]]
    for name, value in (
        ("Brute-force / authentication", rule_counts["AUTH"]),
        ("Network / port fan-out", rule_counts["NET"]),
        ("Malware hash indicators", rule_counts["MALWARE"]),
        ("Phishing indicators", rule_counts["PHISHING"]),
        ("ML anomaly signals", Alert.query.filter(Alert.anomaly_score.isnot(None), Alert.anomaly_score >= threshold).count()),
        ("Distinct unresolved alert source IPs", db.session.query(db.func.count(db.func.distinct(Alert.source_ip))).filter(Alert.source_ip.isnot(None), Alert.status.notin_(("RESOLVED", "FALSE_POSITIVE"))).scalar() or 0),
    ):
        threat_rows.append([paragraph(name), paragraph(value)])
    story.extend([
        Paragraph("Threat Summary", styles["SectionTitle"]),
        styled_table(threat_rows, [4.3 * inch, 0.98 * inch]),
        Paragraph("Incident Summary", styles["SectionTitle"]),
    ])

    incidents = Incident.query.order_by(Incident.created_at.desc()).limit(current_app.config["REPORT_MAX_RECORDS"]).all()
    if incidents:
        for incident in incidents:
            story.append(Paragraph(f"Incident #{incident.id}: {escape(incident.title)}", styles["Heading3"]))
            story.append(paragraph(
                f"Severity: {incident.severity} · Status: {incident.status} · "
                f"Assigned: {incident.assigned_to.username if incident.assigned_to else 'Unassigned'} · "
                f"Created: {incident.created_at.isoformat()}",
                styles["ReportSmall"],
            ))
            story.append(paragraph(f"Description: {incident.description}", styles["ReportSmall"]))
            linked_alerts = [link.alert for link in incident.alert_links if link.alert]
            story.append(paragraph(
                f"Related alerts: {', '.join(f'#{item.id} {item.title}' for item in linked_alerts) or 'None'}",
                styles["ReportSmall"],
            ))
            evidence_events = {
                link.event.id: link.event
                for alert in linked_alerts
                for link in alert.event_links
                if link.event
            }
            for event in sorted(evidence_events.values(), key=lambda item: item.timestamp)[:10]:
                story.append(paragraph(
                    f"Evidence · {event.timestamp.isoformat()} · {event.event_type} · "
                    f"{event.source_ip or 'unknown source'} · {event.message or event.status or 'No details'}",
                    styles["ReportSmall"],
                ))
            for note in incident.notes or []:
                story.append(paragraph(f"Analyst note · {note.get('created_at', '')} · {note.get('note', '')}", styles["ReportSmall"]))
            story.append(paragraph(f"Resolution: {incident.resolution or 'Not recorded'}", styles["ReportSmall"]))
            story.append(Spacer(1, 7))
    else:
        story.append(paragraph("No incidents are available for this report."))

    story.extend([
        PageBreak(),
        Paragraph(f"Selected Records · {escape(data['report_type'].title())}", styles["SectionTitle"]),
    ])
    record_rows = [[paragraph(label) for label in ("ID", "Timestamp", "Severity", "Status", "Summary")]]
    for item in data["items"][:200]:
        record_rows.append([
            paragraph(item.get("id")),
            paragraph(item.get("created_at") or item.get("timestamp")),
            paragraph(item.get("severity")),
            paragraph(item.get("status")),
            paragraph(item.get("title") or item.get("event_type") or item.get("description")),
        ])
    if len(record_rows) == 1:
        record_rows.append([paragraph("No matching records"), paragraph(""), paragraph(""), paragraph(""), paragraph("")])
    story.append(styled_table(record_rows, [0.45 * inch, 1.42 * inch, 0.72 * inch, 0.9 * inch, 2.79 * inch]))
    story.append(Spacer(1, 8))
    story.append(paragraph(
        f"Selected-record section contains at most 200 of {data['record_count']} records. "
        "Threat and anomaly signals are not proof of malicious activity; validate them using authorized telemetry.",
        styles["ReportSmall"],
    ))
    document.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    content = output.getvalue()
    return content
