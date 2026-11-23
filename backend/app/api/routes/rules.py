"""Detection rules, detection runs and experimental anomaly detection."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.anomaly import service as anomaly_service
from app.api.utils import paginate
from app.core.errors import AppError, NotFound
from app.database.session import get_db
from app.detection.engine import run_detection
from app.models import AnomalyResult, DetectionRule, User
from app.schemas.common import Page
from app.schemas.domain import AnomalyOut, AnomalyReview, DetectionRunRequest, RuleOut, RuleUpdate
from app.security.deps import require
from app.security.permissions import Perm
from app.services import app_settings, audit

router = APIRouter(tags=["detection"])


@router.get("/rules", response_model=list[RuleOut])
def list_rules(_: User = Depends(require(Perm.RULES_READ)), db: Session = Depends(get_db)):
    return db.query(DetectionRule).order_by(DetectionRule.id).all()


@router.get("/rules/{rule_id}", response_model=RuleOut)
def get_rule(rule_id: str, _: User = Depends(require(Perm.RULES_READ)), db: Session = Depends(get_db)):
    rule = db.get(DetectionRule, rule_id)
    if rule is None:
        raise NotFound("Rule")
    return rule


def _validate_parameters(current: dict, changes: dict) -> dict:
    """Only existing parameters may change, and each keeps its type. Numbers must be positive."""
    merged = dict(current)
    for key, value in changes.items():
        if key not in current:
            raise AppError(f"Unknown parameter '{key}' for this rule", 422, "validation_error")
        old = current[key]
        if isinstance(old, bool):
            ok = isinstance(value, bool)
        elif isinstance(old, (int, float)):
            ok = isinstance(value, (int, float)) and not isinstance(value, bool) and 0 < value <= 100_000
            if ok and isinstance(old, int) and not isinstance(old, bool):
                ok = float(value).is_integer()
                value = int(value)
        elif isinstance(old, list):
            ok = isinstance(value, list) and len(value) <= 200 and all(isinstance(v, str) and 0 < len(v) <= 200 for v in value)
            value = [v.strip() for v in value] if ok else value
        else:
            ok = isinstance(value, type(old))
        if not ok:
            raise AppError(f"Invalid value for parameter '{key}'", 422, "validation_error")
        merged[key] = value
    return merged


@router.patch("/rules/{rule_id}", response_model=RuleOut)
def update_rule(rule_id: str, body: RuleUpdate, user: User = Depends(require(Perm.RULES_MANAGE)),
                db: Session = Depends(get_db)):
    rule = db.get(DetectionRule, rule_id)
    if rule is None:
        raise NotFound("Rule")
    changes = body.model_dump(exclude_none=True)
    before = {k: getattr(rule, k) for k in changes}
    if "parameters" in changes:
        rule.parameters = _validate_parameters(rule.parameters, changes["parameters"])
    for key in ("enabled", "severity", "base_score", "confidence"):
        if key in changes:
            setattr(rule, key, changes[key])
    rule.updated_by_id = user.id
    audit.record(db, "rule.update", actor=user, object_type="rule", object_id=rule.id,
                 details={"before": before, "after": {k: getattr(rule, k) for k in changes}})
    db.commit()
    db.refresh(rule)
    return rule


@router.post("/detection/run")
def run(body: DetectionRunRequest, user: User = Depends(require(Perm.DETECTION_RUN)), db: Session = Depends(get_db)):
    """Run the deterministic detection engine over stored events. Safe to repeat: existing
    evidence is never alerted twice."""
    return run_detection(db, job_id=body.job_id, start=body.start, end=body.end, actor=user, rule_ids=body.rule_ids)


# ---- anomaly detection (experimental) --------------------------------------------------------

@router.get("/anomaly/status")
def anomaly_status(_: User = Depends(require(Perm.RULES_READ)), db: Session = Depends(get_db)):
    return {"enabled": bool(app_settings.get(db, "anomaly_detection_enabled")),
            "features": anomaly_service.FEATURES, "model_version": anomaly_service.MODEL_VERSION,
            "min_rows": anomaly_service.MIN_ROWS, "contamination": app_settings.get(db, "anomaly_contamination")}


@router.post("/anomaly/run")
def anomaly_run(days: int = Query(30, ge=1, le=365), user: User = Depends(require(Perm.ANOMALY_RUN)),
                db: Session = Depends(get_db)):
    return anomaly_service.run(db, user, days)


@router.get("/anomaly/results", response_model=Page[AnomalyOut])
def anomaly_results(review_status: str | None = None, page: int = Query(1, ge=1),
                    page_size: int = Query(25, ge=1, le=200), _: User = Depends(require(Perm.RULES_READ)),
                    db: Session = Depends(get_db)):
    query = db.query(AnomalyResult)
    if review_status:
        query = query.filter(AnomalyResult.review_status == review_status)
    return paginate(query.order_by(AnomalyResult.anomaly_score.desc()), page, page_size)


@router.post("/anomaly/results/{result_id}/review", response_model=AnomalyOut)
def anomaly_review(result_id: int, body: AnomalyReview, user: User = Depends(require(Perm.ANOMALY_RUN)),
                   db: Session = Depends(get_db)):
    return anomaly_service.review(db, result_id, body.status, body.note, user)
