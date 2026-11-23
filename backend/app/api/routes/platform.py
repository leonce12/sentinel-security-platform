"""Dashboard, AI analyst, reports, notifications, audit logs, settings, demo data and health."""

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import text
from sqlalchemy.orm import Session, undefer

from app.ai import service as ai_service
from app.ai.glossary import GLOSSARY
from app.api.serializers import UserCache
from app.api.utils import paginate
from app.core.errors import AppError, NotFound
from app.database.session import get_db
from app.incidents import alerts as alert_service, incidents as incident_service
from app.models import AuditLog, Notification, Report, User
from app.reporting import service as report_service
from app.schemas.common import Message, Page
from app.schemas.domain import AskRequest, AuditOut, NotificationOut, ReportOut, ReportRequest, ResetConfirm
from app.security.deps import get_current_user, require
from app.security.permissions import Perm
from app.services import app_settings, audit, dashboard, demo, export

router = APIRouter()


# ---- dashboard -------------------------------------------------------------------------------
@router.get("/dashboard/summary", tags=["dashboard"])
def dashboard_summary(start: datetime | None = None, end: datetime | None = None,
                      _: User = Depends(require(Perm.DASHBOARD_READ)), db: Session = Depends(get_db)):
    return dashboard.summary(db, start, end)


@router.get("/dashboard/analytics", tags=["dashboard"])
def dashboard_analytics(start: datetime | None = None, end: datetime | None = None,
                        _: User = Depends(require(Perm.DASHBOARD_READ)), db: Session = Depends(get_db)):
    return dashboard.analytics(db, start, end)


# ---- AI analyst ------------------------------------------------------------------------------
@router.get("/ai/status", tags=["ai"])
def ai_status(_: User = Depends(require(Perm.AI_USE)), db: Session = Depends(get_db)):
    return ai_service.status(db)


@router.get("/ai/glossary", tags=["ai"])
def glossary(_: User = Depends(get_current_user)):
    return [{"term": k, "definition": v} for k, v in sorted(GLOSSARY.items())]


@router.post("/ai/explain/alert/{alert_id}", tags=["ai"])
def explain_alert(alert_id: int, user: User = Depends(require(Perm.AI_USE)), db: Session = Depends(get_db)):
    return ai_service.explain_alert(db, alert_service.get_alert(db, alert_id), user)


@router.post("/ai/summarize/incident/{incident_id}", tags=["ai"])
def summarize_incident(incident_id: int, user: User = Depends(require(Perm.AI_USE)), db: Session = Depends(get_db)):
    return ai_service.summarize_incident(db, incident_service.get_incident(db, incident_id), user)


@router.post("/ai/ask", tags=["ai"])
def ask(body: AskRequest, user: User = Depends(require(Perm.AI_USE)), db: Session = Depends(get_db)):
    return ai_service.ask(db, body.question, user)


# ---- reports ---------------------------------------------------------------------------------
def _report_out(report: Report, users: UserCache) -> ReportOut:
    return ReportOut(id=report.id, report_type=report.report_type, title=report.title, parameters=report.parameters,
                     period_start=report.period_start, period_end=report.period_end, summary=report.summary,
                     sha256=report.sha256, size_bytes=report.size_bytes, generated_by=users.ref(report.generated_by_id),
                     generated_at=report.generated_at)


@router.post("/reports", response_model=ReportOut, status_code=201, tags=["reports"])
def create_report(body: ReportRequest, user: User = Depends(require(Perm.REPORTS_GENERATE)), db: Session = Depends(get_db)):
    report = report_service.generate(db, body.report_type, user, day=body.date, start_date=body.start_date,
                                     incident_id=body.incident_id)
    return _report_out(report, UserCache(db))


@router.get("/reports", response_model=Page[ReportOut], tags=["reports"])
def list_reports(report_type: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
                 _: User = Depends(require(Perm.REPORTS_READ)), db: Session = Depends(get_db)):
    query = db.query(Report)
    if report_type:
        query = query.filter(Report.report_type == report_type)
    users = UserCache(db)
    return paginate(query.order_by(Report.generated_at.desc()), page, page_size, lambda r: _report_out(r, users))


@router.get("/reports/{report_id}/download", tags=["reports"])
def download_report(report_id: int, user: User = Depends(require(Perm.REPORTS_READ)), db: Session = Depends(get_db)):
    report = db.query(Report).options(undefer(Report.content)).filter(Report.id == report_id).first()
    if report is None:
        raise NotFound("Report")
    audit.record(db, "report.download", actor=user, object_type="report", object_id=report.id, commit=True)
    filename = f"sentinel-{report.report_type}-report-{report.id}.pdf"
    return Response(report.content, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"', "X-Report-SHA256": report.sha256})


# ---- notifications ---------------------------------------------------------------------------
@router.get("/notifications", response_model=Page[NotificationOut], tags=["notifications"])
def notifications_list(unread: bool | None = None, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
                       user: User = Depends(require(Perm.NOTIFICATIONS_READ)), db: Session = Depends(get_db)):
    query = db.query(Notification).filter(Notification.user_id == user.id)  # users only ever see their own
    if unread is not None:
        query = query.filter(Notification.is_read.is_(not unread))
    return paginate(query.order_by(Notification.created_at.desc(), Notification.id.desc()), page, page_size)


@router.get("/notifications/unread-count", tags=["notifications"])
def unread_count(user: User = Depends(require(Perm.NOTIFICATIONS_READ)), db: Session = Depends(get_db)):
    return {"count": db.query(Notification).filter_by(user_id=user.id, is_read=False).count()}


@router.post("/notifications/{notification_id}/read", response_model=NotificationOut, tags=["notifications"])
def mark_read(notification_id: int, user: User = Depends(require(Perm.NOTIFICATIONS_READ)), db: Session = Depends(get_db)):
    item = db.query(Notification).filter_by(id=notification_id, user_id=user.id).first()
    if item is None:
        raise NotFound("Notification")
    item.is_read = True
    db.commit()
    return item


@router.post("/notifications/read-all", response_model=Message, tags=["notifications"])
def mark_all_read(user: User = Depends(require(Perm.NOTIFICATIONS_READ)), db: Session = Depends(get_db)):
    count = db.query(Notification).filter_by(user_id=user.id, is_read=False).update({"is_read": True})
    db.commit()
    return Message(message=f"{count} notification(s) marked as read")


# ---- audit logs (read only; there are no update or delete endpoints) -------------------------
def _audit_query(db, q, action, actor, outcome, start, end):
    query = db.query(AuditLog)
    if q:
        query = query.filter(AuditLog.action.ilike(f"%{q}%") | AuditLog.actor_username.ilike(f"%{q}%") |
                             AuditLog.object_id.ilike(f"%{q}%"))
    if action:
        query = query.filter(AuditLog.action == action)
    if actor:
        query = query.filter(AuditLog.actor_username == actor)
    if outcome:
        query = query.filter(AuditLog.outcome == outcome)
    if start:
        query = query.filter(AuditLog.created_at >= start)
    if end:
        query = query.filter(AuditLog.created_at <= end)
    return query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())


@router.get("/audit-logs", response_model=Page[AuditOut], tags=["audit"])
def audit_logs(q: str | None = Query(None, max_length=100), action: str | None = None, actor: str | None = None,
               outcome: str | None = None, start: datetime | None = None, end: datetime | None = None,
               page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
               _: User = Depends(require(Perm.AUDIT_READ)), db: Session = Depends(get_db)):
    return paginate(_audit_query(db, q, action, actor, outcome, start, end), page, page_size)


@router.get("/audit-logs/export", tags=["audit"])
def audit_export(q: str | None = None, action: str | None = None, actor: str | None = None, outcome: str | None = None,
                 start: datetime | None = None, end: datetime | None = None,
                 user: User = Depends(require(Perm.AUDIT_READ)), db: Session = Depends(get_db)):
    columns = ["id", "created_at", "actor_username", "action", "object_type", "object_id", "outcome", "ip_address", "details"]
    rows = export.model_rows(_audit_query(db, q, action, actor, outcome, start, end).limit(export.MAX_EXPORT_ROWS), columns)
    audit.record(db, "export.audit_logs", actor=user, details={"rows": len(rows)}, commit=True)
    return Response(export.to_csv(rows, columns), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="sentinel-audit-log.csv"'})


# ---- settings & demo -------------------------------------------------------------------------
@router.get("/settings", tags=["settings"])
def get_settings_route(_: User = Depends(require(Perm.SETTINGS_MANAGE)), db: Session = Depends(get_db)):
    from app.core.config import get_settings
    env = get_settings()
    return {"settings": app_settings.get_all(db),
            "environment": {"ai_provider": env.ai_provider, "ai_provider_configured": ai_service.get_provider() is not None,
                            "virustotal_configured": bool(env.virustotal_api_key), "max_upload_mb": env.max_upload_mb,
                            "environment": env.environment}}


@router.patch("/settings", tags=["settings"])
def update_settings(changes: dict, user: User = Depends(require(Perm.SETTINGS_MANAGE)), db: Session = Depends(get_db)):
    if not changes:
        raise AppError("No changes supplied", 422, "validation_error")
    return {"settings": app_settings.update(db, changes, user)}


@router.post("/demo/load", tags=["demo"])
def demo_load(user: User = Depends(require(Perm.DEMO_MANAGE)), db: Session = Depends(get_db)):
    return demo.load_demo(db, user)


@router.post("/demo/reset", tags=["demo"])
def demo_reset(body: ResetConfirm, user: User = Depends(require(Perm.DEMO_MANAGE)), db: Session = Depends(get_db)):
    return demo.reset_demo(db, user)


# ---- health ----------------------------------------------------------------------------------
@router.get("/health", tags=["health"])
def health():
    return {"status": "ok"}


@router.get("/health/ready", tags=["health"])
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        return Response('{"status":"unavailable","database":"unreachable"}', status_code=503, media_type="application/json")
    return {"status": "ok", "database": db.bind.dialect.name, "ai": "optional", "threat_intel": "optional"}
