"""Experimental anomaly detection with an Isolation Forest.

What it does
  Builds one feature row per (account, hour) from stored events, learns what is typical
  across all rows, and scores how unusual each row is. Results are advisory: they are
  stored for analyst review and never create alerts or incidents on their own.

Features (per account per hour)
  event_count, auth_failures, auth_successes, distinct_source_ips, distinct_resources,
  access_denied, off_hours (1 if the hour is outside business hours)

Explanation
  For every flagged row we report the features whose value is furthest from the
  baseline mean (z-score above 2), so an analyst can see why it was flagged.

Limitations (also in docs/detection-rules.md)
  * Needs enough history; with fewer than 50 rows the model refuses to run.
  * Contamination is an assumption about how much activity is unusual, not a measurement.
  * Unusual is not malicious. It is a prompt to look, never a verdict.
"""

from datetime import UTC, datetime, timedelta

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.models import AnomalyResult, SecurityEvent, User
from app.services import app_settings, audit

FEATURES = ["event_count", "auth_failures", "auth_successes", "distinct_source_ips", "distinct_resources",
            "access_denied", "off_hours"]
MODEL_VERSION = "isolation-forest-v1"
MIN_ROWS = 50


def build_features(events: pd.DataFrame, business_hours: tuple[int, int]) -> pd.DataFrame:
    """events columns: timestamp, username, event_category, outcome, source_ip, resource, is_synthetic."""
    if events.empty:
        return pd.DataFrame(columns=["entity", "window_start", *FEATURES, "is_synthetic"])
    df = events.dropna(subset=["username"]).copy()
    df["window_start"] = pd.to_datetime(df["timestamp"], utc=True).dt.floor("h")
    df["is_auth"] = df["event_category"] == "authentication"
    df["auth_failure"] = df["is_auth"] & (df["outcome"] == "failure")
    df["auth_success"] = df["is_auth"] & (df["outcome"] == "success")
    df["access_denied"] = (df["event_category"] == "access") & (df["outcome"] == "failure")
    grouped = df.groupby(["username", "window_start"])
    features = pd.DataFrame({
        "event_count": grouped.size(),
        "auth_failures": grouped["auth_failure"].sum(),
        "auth_successes": grouped["auth_success"].sum(),
        "distinct_source_ips": grouped["source_ip"].nunique(),
        "distinct_resources": grouped["resource"].nunique(),
        "access_denied": grouped["access_denied"].sum(),
        "is_synthetic": grouped["is_synthetic"].all(),
    }).reset_index()
    start, end = business_hours
    hours = features["window_start"].dt.hour
    features["off_hours"] = (~((hours >= start) & (hours < end))).astype(int)
    features["entity"] = "username:" + features["username"]
    return features.drop(columns=["username"])


def fit_and_score(features: pd.DataFrame, contamination: float) -> pd.DataFrame:
    if len(features) < MIN_ROWS:
        raise AppError(f"Anomaly detection needs at least {MIN_ROWS} account-hours of history "
                       f"(found {len(features)}). Ingest more events first.", 422, "insufficient_data")
    matrix = features[FEATURES].astype(float).to_numpy()
    pipeline = Pipeline([
        ("impute", SimpleImputer(strategy="median")),  # missing values -> median
        ("scale", StandardScaler()),  # put counts on comparable scales
        ("model", IsolationForest(n_estimators=200, contamination=contamination, random_state=42)),
    ])
    pipeline.fit(matrix)
    # score_samples: higher is more normal. Flip and rescale to 0..1 so higher means more unusual.
    raw = -pipeline.score_samples(matrix)
    scaled = (raw - raw.min()) / (raw.max() - raw.min() or 1)
    out = features.copy()
    out["anomaly_score"] = np.round(scaled, 4)
    out["is_anomaly"] = pipeline.predict(matrix) == -1

    means = features[FEATURES].astype(float).mean()
    stds = features[FEATURES].astype(float).std(ddof=0).replace(0, 1)
    contributions = []
    for _, row in features.iterrows():
        items = []
        for name in FEATURES:
            z = (float(row[name]) - means[name]) / stds[name]
            if abs(z) >= 2:
                items.append({"feature": name, "value": float(row[name]), "baseline_mean": round(float(means[name]), 2),
                              "z_score": round(float(z), 2)})
        contributions.append(sorted(items, key=lambda i: -abs(i["z_score"]))[:4])
    out["contributing_features"] = contributions
    return out


def run(db: Session, actor: User, days: int = 30) -> dict:
    if not app_settings.get(db, "anomaly_detection_enabled"):
        raise AppError("Anomaly detection is disabled. An administrator can enable it in Settings.", 409, "disabled")
    latest = db.query(SecurityEvent.timestamp).order_by(SecurityEvent.timestamp.desc()).first()
    if latest is None:
        raise AppError("No events stored yet", 422, "insufficient_data")
    since = latest[0] - timedelta(days=days)
    rows = (db.query(SecurityEvent.timestamp, SecurityEvent.username, SecurityEvent.event_category,
                     SecurityEvent.outcome, SecurityEvent.source_ip, SecurityEvent.resource, SecurityEvent.is_synthetic)
            .filter(SecurityEvent.timestamp >= since).all())
    events = pd.DataFrame(rows, columns=["timestamp", "username", "event_category", "outcome", "source_ip",
                                         "resource", "is_synthetic"])
    business = (app_settings.get(db, "business_hours_start"), app_settings.get(db, "business_hours_end"))
    features = build_features(events, business)
    scored = fit_and_score(features, float(app_settings.get(db, "anomaly_contamination")))

    # Replace previous unreviewed results for the same period; keep anything an analyst reviewed.
    db.query(AnomalyResult).filter(AnomalyResult.window_start >= since,
                                   AnomalyResult.review_status == "unreviewed").delete(synchronize_session=False)
    reviewed = {(r.entity, r.window_start) for r in db.query(AnomalyResult.entity, AnomalyResult.window_start)
                .filter(AnomalyResult.window_start >= since)}
    stored = 0
    for _, row in scored[scored["is_anomaly"]].iterrows():
        start = row["window_start"].to_pydatetime()
        if (row["entity"], start) in reviewed:
            continue
        db.add(AnomalyResult(
            entity=row["entity"], window_start=start, window_end=start + timedelta(hours=1),
            features={name: float(row[name]) for name in FEATURES}, anomaly_score=float(row["anomaly_score"]),
            is_anomaly=True, contributing_features=row["contributing_features"], model_version=MODEL_VERSION,
            is_synthetic=bool(row["is_synthetic"]),
        ))
        stored += 1
    summary = {"rows_scored": int(len(scored)), "anomalies": int(scored["is_anomaly"].sum()), "stored": stored,
               "since": since.isoformat(), "model_version": MODEL_VERSION,
               "contamination": app_settings.get(db, "anomaly_contamination"),
               "ran_at": datetime.now(UTC).isoformat()}
    audit.record(db, "anomaly.run", actor=actor, object_type="anomaly", details=summary)
    db.commit()
    return summary


def review(db: Session, result_id: int, status: str, note: str, actor: User) -> AnomalyResult:
    result = db.get(AnomalyResult, result_id)
    if result is None:
        from app.core.errors import NotFound
        raise NotFound("Anomaly result")
    result.review_status = status
    result.review_note = note.strip()
    result.reviewed_by_id = actor.id
    result.reviewed_at = datetime.now(UTC)
    audit.record(db, "anomaly.review", actor=actor, object_type="anomaly", object_id=result.id,
                 details={"status": status})
    db.commit()
    return result
