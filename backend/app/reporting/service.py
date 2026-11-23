"""PDF report generation (ReportLab). Reports are built from database records at generation
time and stored with metadata and a SHA-256 hash so later copies can be verified."""

import hashlib
import io
from datetime import UTC, date, datetime, time, timedelta
from xml.sax.saxutils import escape  # nosec B406 (escapes PDF output; nothing is parsed)

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.errors import AppError, NotFound
from app.incidents.alerts import OPEN_STATUSES
from app.models import Alert, AlertEvent, DetectionRule, Incident, IncidentHistory, IncidentNote, Report, SecurityEvent, User
from app.services import audit

NAVY = colors.HexColor("#0f172a")
GRID = colors.HexColor("#cbd5e1")
_styles = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=_styles["Heading1"], textColor=NAVY, fontSize=18, spaceAfter=4)
H2 = ParagraphStyle("h2", parent=_styles["Heading2"], textColor=NAVY, fontSize=13, spaceBefore=10, spaceAfter=4)
BODY = ParagraphStyle("body", parent=_styles["BodyText"], fontSize=9.5, leading=13)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=8, textColor=colors.HexColor("#475569"))


def P(text, style=BODY) -> Paragraph:
    """Escape every value: report content comes from logs and must not inject markup."""
    return Paragraph(escape(str(text)), style)


def table(rows: list[list], widths=None) -> Table:
    data = [[P(c, SMALL) if not isinstance(c, Paragraph) else c for c in r] for r in rows]
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ("GRID", (0, 0), (-1, -1), 0.4, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _header(story: list, title: str, meta: dict, actor: User) -> None:
    story.append(P(title, H1))
    story.append(P(f"Generated {datetime.now(UTC):%Y-%m-%d %H:%M UTC} by {actor.username} | Sentinel", SMALL))
    for key, value in meta.items():
        story.append(P(f"{key}: {value}", SMALL))
    story.append(Spacer(1, 6))


def _render(story: list) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm,
                            bottomMargin=14 * mm, title="Sentinel report", author="Sentinel")

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(16 * mm, 8 * mm, "Sentinel security report. Detections indicate suspicious activity that "
                                           "requires investigation; they are not confirmed attacks.")
        canvas.drawRightString(A4[0] - 16 * mm, 8 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def _period_stats(db: Session, start: datetime, end: datetime) -> dict:
    events = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= start, SecurityEvent.timestamp < end)
    alerts = db.query(Alert).filter(Alert.last_seen >= start, Alert.first_seen < end)
    return {
        "events": events.count(),
        "synthetic_events": events.filter(SecurityEvent.is_synthetic.is_(True)).count(),
        "alerts": alerts.count(),
        "alerts_by_severity": dict(alerts.with_entities(Alert.severity, func.count()).group_by(Alert.severity).all()),
        "events_by_severity": dict(events.with_entities(SecurityEvent.severity, func.count()).group_by(SecurityEvent.severity).all()),
        "incidents_opened": db.query(Incident).filter(Incident.detected_at >= start, Incident.detected_at < end).count(),
        "incidents_open_now": db.query(Incident).filter(Incident.status.in_(("open", "investigating", "contained"))).count(),
        "auth_failures": events.filter(SecurityEvent.event_category == "authentication",
                                       SecurityEvent.outcome == "failure").count(),
        "top_rules": [(r, n) for r, n in alerts.with_entities(Alert.rule_id, func.count()).group_by(Alert.rule_id)
                      .order_by(func.count().desc()).limit(10).all()],
        "top_alerts": alerts.order_by(Alert.risk_score.desc()).limit(10).all(),
    }


def _observations(stats: dict) -> list[str]:
    notes = []
    if stats["events"] == 0:
        return ["No events were stored for this period."]
    if stats["alerts"] == 0:
        notes.append("No detection rule produced an alert in this period.")
    crit = stats["alerts_by_severity"].get("critical", 0)
    if crit:
        notes.append(f"{crit} critical alert(s) need prompt review.")
    if stats["auth_failures"]:
        notes.append(f"{stats['auth_failures']} failed authentication events were recorded.")
    if stats["incidents_open_now"]:
        notes.append(f"{stats['incidents_open_now']} incident(s) remain open.")
    if stats["synthetic_events"]:
        notes.append(f"{stats['synthetic_events']} of the events are synthetic demonstration data.")
    return notes


def _summary_story(db: Session, title: str, start: datetime, end: datetime, actor: User, weekly: bool) -> tuple[list, dict]:
    stats = _period_stats(db, start, end)
    story: list = []
    _header(story, title, {"Period": f"{start:%Y-%m-%d %H:%M} to {end:%Y-%m-%d %H:%M} UTC"}, actor)
    story.append(P("Overview", H2))
    story.append(table([["Metric", "Value"], ["Total events", stats["events"]], ["Total alerts", stats["alerts"]],
                        ["Incidents opened in period", stats["incidents_opened"]],
                        ["Incidents open now", stats["incidents_open_now"]],
                        ["Failed authentications", stats["auth_failures"]]], [90 * mm, 40 * mm]))
    story.append(P("Severity distribution", H2))
    sev = ["informational", "low", "medium", "high", "critical"]
    story.append(table([["Severity", "Events", "Alerts"]] +
                       [[s, stats["events_by_severity"].get(s, 0), stats["alerts_by_severity"].get(s, 0)] for s in sev],
                       [50 * mm, 40 * mm, 40 * mm]))
    if weekly:
        story.append(P("Activity trend (events per day)", H2))
        days = []
        cursor = start
        while cursor < end:
            nxt = cursor + timedelta(days=1)
            n = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= cursor, SecurityEvent.timestamp < nxt).count()
            a = db.query(Alert).filter(Alert.first_seen >= cursor, Alert.first_seen < nxt).count()
            days.append([f"{cursor:%a %Y-%m-%d}", n, a])
            cursor = nxt
        story.append(table([["Day", "Events", "New alerts"]] + days, [60 * mm, 35 * mm, 35 * mm]))
        story.append(P("Top detection categories", H2))
        names = dict(db.query(DetectionRule.id, DetectionRule.name).all())
        story.append(table([["Rule", "Name", "Alerts"]] + ([[r, names.get(r, ""), n] for r, n in stats["top_rules"]]
                            or [["-", "No alerts", 0]]), [32 * mm, 100 * mm, 25 * mm]))
        open_inc = db.query(Incident).filter(Incident.status.in_(("open", "investigating", "contained"))) \
            .order_by(Incident.risk_score.desc()).limit(15).all()
        story.append(P("Open incidents", H2))
        story.append(table([["Reference", "Title", "Status", "Risk"]] +
                           ([[i.reference, i.title, i.status, i.risk_score] for i in open_inc] or [["-", "None", "", ""]]),
                           [30 * mm, 100 * mm, 25 * mm, 15 * mm]))
    story.append(P("Highest-risk alerts", H2))
    story.append(table([["ID", "Title", "Rule", "Score", "Status"]] +
                       ([[a.id, a.title, a.rule_id, a.risk_score, a.status] for a in stats["top_alerts"]]
                        or [["-", "No alerts in this period", "", "", ""]]),
                       [12 * mm, 95 * mm, 30 * mm, 15 * mm, 25 * mm]))
    story.append(P("Important observations" if not weekly else "Recommended areas for review", H2))
    for note in _observations(stats):
        story.append(P(f"- {note}"))
    if weekly:
        repeated = [r for r, n in stats["top_rules"] if n >= 3]
        if repeated:
            story.append(P(f"- Repeated patterns: rules {', '.join(repeated)} fired three or more times; review thresholds "
                           "and recurring sources."))
    summary = {k: v for k, v in stats.items() if k not in ("top_alerts", "top_rules")}
    summary["top_rules"] = [list(x) for x in stats["top_rules"]]
    return story, summary


def _incident_story(db: Session, incident: Incident, actor: User) -> tuple[list, dict]:
    story: list = []
    assignee = db.get(User, incident.assigned_to_id) if incident.assigned_to_id else None
    _header(story, f"Incident report {incident.reference}", {
        "Title": incident.title, "Status": incident.status, "Severity": incident.severity,
        "Risk score": incident.risk_score, "Assigned analyst": assignee.username if assignee else "Unassigned",
        "Detected": f"{incident.detected_at:%Y-%m-%d %H:%M UTC}",
        "Data": "Synthetic demonstration data" if incident.is_synthetic else "Ingested records",
    }, actor)
    story.append(P("Overview", H2))
    story.append(P(incident.description or "No description recorded."))
    entities = incident.affected_entities or {}
    story.append(P("Affected entities", H2))
    story.append(table([["Type", "Values"]] + [[k, ", ".join(entities.get(k, [])) or "-"] for k in ("accounts", "systems", "ips")],
                       [30 * mm, 145 * mm]))
    alerts = db.query(Alert).filter(Alert.incident_id == incident.id).order_by(Alert.first_seen).all()
    story.append(P("Associated alerts and risk assessment", H2))
    story.append(table([["ID", "Rule", "Title", "Score", "Events", "Status"]] +
                       ([[a.id, a.rule_id, a.title, a.risk_score, a.event_count, a.status] for a in alerts]
                        or [["-", "", "No linked alerts", "", "", ""]]),
                       [12 * mm, 28 * mm, 85 * mm, 14 * mm, 15 * mm, 22 * mm]))
    for a in alerts[:5]:
        story.append(P(f"Score factors for alert #{a.id}", SMALL))
        story.append(table([["Factor", "Points", "Explanation"]] +
                           [[f["factor"], f["points"], f["explanation"]] for f in a.score_breakdown],
                           [45 * mm, 15 * mm, 115 * mm]))
    event_ids = [r[0] for r in db.query(AlertEvent.event_id).filter(AlertEvent.alert_id.in_([a.id for a in alerts]))] if alerts else []
    events = (db.query(SecurityEvent).filter(SecurityEvent.id.in_(event_ids)).order_by(SecurityEvent.timestamp).limit(40).all()
              if event_ids else [])
    story.append(P(f"Evidence ({len(event_ids)} event(s), first {len(events)} shown)", H2))
    story.append(table([["Time (UTC)", "System", "Type", "User", "Source IP", "Outcome"]] +
                       ([[f"{e.timestamp:%Y-%m-%d %H:%M:%S}", e.source_system, e.event_type, e.username or "-",
                         e.source_ip or "-", e.outcome or "-"] for e in events] or [["-", "", "", "", "", ""]]),
                       [32 * mm, 35 * mm, 38 * mm, 25 * mm, 28 * mm, 17 * mm]))
    history = db.query(IncidentHistory).filter_by(incident_id=incident.id).order_by(IncidentHistory.created_at).all()
    users = {u.id: u.username for u in db.query(User).all()}
    story.append(P("Timeline", H2))
    story.append(table([["Time (UTC)", "Change", "From", "To", "By", "Details"]] +
                       [[f"{h.created_at:%Y-%m-%d %H:%M}", h.change_type, h.from_value or "", h.to_value or "",
                         users.get(h.actor_id, "system"), h.details[:120]] for h in history],
                       [28 * mm, 25 * mm, 22 * mm, 25 * mm, 20 * mm, 55 * mm]))
    notes = db.query(IncidentNote).filter_by(incident_id=incident.id).order_by(IncidentNote.created_at).all()
    story.append(P("Investigation notes", H2))
    if not notes:
        story.append(P("No investigation notes recorded."))
    for n in notes:
        story.append(P(f"{n.created_at:%Y-%m-%d %H:%M} {users.get(n.author_id, 'unknown')}:", SMALL))
        story.append(P(n.body))
    story.append(P("Resolution status", H2))
    story.append(P(f"Status: {incident.status}. " + (f"Resolution: {incident.resolution}" if incident.resolution
                                                      else "No resolution recorded yet.")))
    if incident.closed_at:
        story.append(P(f"Closed at {incident.closed_at:%Y-%m-%d %H:%M UTC}."))
    return story, {"alerts": len(alerts), "events": len(event_ids), "notes": len(notes), "status": incident.status}


def generate(db: Session, report_type: str, actor: User, *, day: date | None = None, start_date: date | None = None,
             incident_id: int | None = None) -> Report:
    if report_type == "daily":
        day = day or datetime.now(UTC).date()
        start = datetime.combine(day, time.min, tzinfo=UTC)
        end = start + timedelta(days=1)
        story, summary = _summary_story(db, f"Daily security report {day.isoformat()}", start, end, actor, weekly=False)
        title, params = f"Daily security report {day.isoformat()}", {"date": day.isoformat()}
    elif report_type == "weekly":
        start_date = start_date or (datetime.now(UTC).date() - timedelta(days=6))
        start = datetime.combine(start_date, time.min, tzinfo=UTC)
        end = start + timedelta(days=7)
        title = f"Weekly security report {start_date.isoformat()} to {(start_date + timedelta(days=6)).isoformat()}"
        story, summary = _summary_story(db, title, start, end, actor, weekly=True)
        params = {"start_date": start_date.isoformat()}
    elif report_type == "incident":
        if incident_id is None:
            raise AppError("incident_id is required for incident reports", 422, "validation_error")
        incident = db.get(Incident, incident_id)
        if incident is None:
            raise NotFound("Incident")
        story, summary = _incident_story(db, incident, actor)
        title, params, start, end = f"Incident report {incident.reference}", {"incident_id": incident_id}, None, None
    else:
        raise AppError("Unknown report type", 422, "validation_error")

    pdf = _render(story)
    report = Report(report_type=report_type, title=title, parameters=params, period_start=start, period_end=end,
                    summary=summary, sha256=hashlib.sha256(pdf).hexdigest(), size_bytes=len(pdf), content=pdf,
                    generated_by_id=actor.id)
    db.add(report)
    db.flush()
    audit.record(db, "report.generate", actor=actor, object_type="report", object_id=report.id,
                 details={"type": report_type, **params})
    db.commit()
    return report
