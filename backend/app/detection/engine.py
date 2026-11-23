"""Detection engine: loads stored events, runs enabled rules, hands findings to the alert service.

Flow for one run:
  1. Decide the evaluated period (one ingestion job, an explicit range, or everything).
  2. For each enabled rule, load events from (start - lookback) to (end + lookback) so
     windows and baselines that straddle the period edges are complete.
  3. Apply the rule's relevance filter and evaluate it.
  4. Keep findings that include at least one event inside the evaluated period.
  5. Create or merge alerts (incidents/alerts.py), which handles duplicates and scoring.
"""

import logging
import time
from datetime import UTC, datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.detection.rules import RULES, DetectionContext, EventView
from app.intelligence.service import reputation_map
from app.models import DetectionRule, SecurityEvent, User
from app.services import app_settings, audit

logger = logging.getLogger("sentinel.detection")


def to_view(e: SecurityEvent) -> EventView:
    return EventView(
        id=e.id, timestamp=e.timestamp, source_system=e.source_system, event_category=e.event_category,
        event_type=e.event_type, severity=e.severity, source_ip=e.source_ip, destination_ip=e.destination_ip,
        username=e.username, action=e.action, outcome=e.outcome, resource=e.resource,
        description=e.description or "", raw=e.raw_data or {},
    )


def build_context(db: Session) -> DetectionContext:
    return DetectionContext(
        business_hours=(app_settings.get(db, "business_hours_start"), app_settings.get(db, "business_hours_end")),
        reputation=reputation_map(db),
    )


def _period(db: Session, job_id: int | None, start: datetime | None, end: datetime | None):
    query = db.query(func.min(SecurityEvent.timestamp), func.max(SecurityEvent.timestamp))
    if job_id is not None:
        query = query.filter(SecurityEvent.ingestion_job_id == job_id)
    lo, hi = query.one()
    return start or lo, end or hi


def run_detection(db: Session, *, job_id: int | None = None, start: datetime | None = None,
                  end: datetime | None = None, actor: User | None = None, rule_ids: list[str] | None = None) -> dict:
    from app.incidents.alerts import process_finding, rescore_run  # local import avoids a cycle

    started = time.perf_counter()
    period_start, period_end = _period(db, job_id, start, end)
    summary = {"rules_evaluated": 0, "events_considered": 0, "findings": 0, "alerts_created": 0,
               "alerts_updated": 0, "unchanged": 0, "incidents_created": 0, "per_rule": {},
               "period_start": period_start.isoformat() if period_start else None,
               "period_end": period_end.isoformat() if period_end else None, "job_id": job_id}
    if period_start is None:
        summary["duration_ms"] = int((time.perf_counter() - started) * 1000)
        return summary

    ctx = build_context(db)
    query = db.query(DetectionRule).filter(DetectionRule.enabled.is_(True))
    if rule_ids:
        query = query.filter(DetectionRule.id.in_(rule_ids))
    considered: set[int] = set()
    touched: set[int] = set()

    for rule_row in query.order_by(DetectionRule.id).all():
        logic = RULES.get(rule_row.id)
        if logic is None:
            logger.warning("No logic registered for rule %s", rule_row.id)
            continue
        params = rule_row.parameters or {}
        lookback = logic.lookback(params)
        event_query = db.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= period_start - lookback,
            SecurityEvent.timestamp <= period_end + lookback,
        )
        if logic.categories:
            event_query = event_query.filter(SecurityEvent.event_category.in_(logic.categories))
        views = [to_view(e) for e in event_query.order_by(SecurityEvent.timestamp, SecurityEvent.id).yield_per(2000)]
        relevant = [v for v in views if logic.relevant(v, params)]
        considered.update(v.id for v in relevant)

        findings = [
            f for f in logic.evaluate(relevant, params, ctx)
            if any(period_start <= e.timestamp <= period_end for e in f.events)
        ]
        stats = {"relevant_events": len(relevant), "findings": len(findings), "created": 0, "updated": 0, "unchanged": 0}
        for finding in findings:
            outcome, alert, incident_created = process_finding(db, rule_row, finding, ctx, actor)
            stats[outcome] += 1
            if alert is not None:
                touched.add(alert.id)
            summary["incidents_created"] += int(incident_created)
        db.commit()
        summary["rules_evaluated"] += 1
        summary["findings"] += len(findings)
        summary["alerts_created"] += stats["created"]
        summary["alerts_updated"] += stats["updated"]
        summary["unchanged"] += stats["unchanged"]
        summary["per_rule"][rule_row.id] = stats

    if touched:
        summary["incidents_created"] += rescore_run(db, touched, ctx.reputation, actor)
        db.commit()
    summary["events_considered"] = len(considered)
    summary["duration_ms"] = int((time.perf_counter() - started) * 1000)
    audit.record(db, "detection.run", actor=actor, actor_username=None if actor else "system",
                 object_type="detection", object_id=job_id,
                 details={k: v for k, v in summary.items() if k != "per_rule"})
    db.commit()
    return summary
