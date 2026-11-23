"""Detection validation suite: each rule against normal, suspicious, borderline, incomplete,
out-of-window and high-volume activity. Rules are tested in isolation (no database)."""

import time
from datetime import timedelta

import pytest

from app.detection.definitions import RULE_DEFINITIONS
from app.detection.rules import RULES, DetectionContext, threshold_bursts
from tests.helpers import BASE, view

PARAMS = {d["id"]: d["parameters"] for d in RULE_DEFINITIONS}
CTX = DetectionContext(business_hours=(7, 19))


def run(rule_id, events, ctx=CTX, params=None):
    rule = RULES[rule_id]
    p = {**PARAMS[rule_id], **(params or {})}
    return rule.evaluate([e for e in events if rule.relevant(e, p)], p, ctx)


def test_every_definition_has_logic_and_documentation():
    assert set(RULES) == set(PARAMS)
    for d in RULE_DEFINITIONS:
        assert d["investigation_steps"] and d["false_positive_notes"] and d["required_fields"] and d["rationale"]


# ---- burst windowing --------------------------------------------------------------------------
def test_threshold_bursts_are_deterministic_and_non_overlapping():
    events = [view(i) for i in range(12)]
    first = threshold_bursts(events, timedelta(minutes=4), 5)
    again = threshold_bursts(list(reversed(events)), timedelta(minutes=4), 5)
    assert [[e.id for e in b] for b in first] == [[e.id for e in b] for b in again]
    ids = [e.id for b in first for e in b]
    assert len(ids) == len(set(ids))


# ---- A. repeated authentication failures --------------------------------------------------------
def test_auth_failures_normal_activity_no_alert():
    events = [view(i * 30) for i in range(4)]  # 4 failures spread over 2 hours
    assert run("SEN-AUTH-001", events) == []


def test_auth_failures_burst_alerts():
    findings = run("SEN-AUTH-001", [view(i * 0.5) for i in range(6)])
    assert len(findings) == 1
    f = findings[0]
    assert f.group_key == "username:alice" and f.count == 6 and f.threshold == 5
    assert "requires investigation" in f.description and "confirmed" not in f.description.lower()


def test_auth_failures_borderline_exactly_threshold():
    assert len(run("SEN-AUTH-001", [view(i * 2) for i in range(5)])) == 1  # 5 in 8 minutes, window 10
    assert run("SEN-AUTH-001", [view(i * 2) for i in range(4)]) == []  # one below threshold


def test_auth_failures_outside_window_not_combined():
    events = [view(i) for i in range(3)] + [view(30 + i) for i in range(3)]  # 3 + 3, 30 minutes apart
    assert run("SEN-AUTH-001", events) == []


def test_auth_successes_ignored_and_missing_user_handled():
    assert run("SEN-AUTH-001", [view(i, outcome="success", event_type="login_success") for i in range(10)]) == []
    events = [view(i * 0.2, username=None) for i in range(6)]  # no username, single source: not spraying
    assert run("SEN-AUTH-001", events) == []


def test_password_spraying_detected_by_source():
    events = [view(i * 0.5, username=f"user{i}", source_ip="203.0.113.9") for i in range(6)]
    findings = run("SEN-AUTH-001", events)
    assert [f.group_key for f in findings] == ["source_ip:203.0.113.9"]
    assert findings[0].extra_points[0]["points"] == 5


# ---- B. unusual login ----------------------------------------------------------------------------
def _logins(user="bob", ip="10.0.0.7", days=4):
    return [view(-24 * 60 * d, username=user, source_ip=ip, outcome="success", event_type="login_success")
            for d in range(days, 0, -1)]


def test_unusual_login_normal_no_alert():
    history = _logins()
    today = view(0, username="bob", source_ip="10.0.0.7", outcome="success", event_type="login_success")
    assert run("SEN-AUTH-002", history + [today]) == []


def test_unusual_login_new_ip_and_off_hours():
    history = _logins()
    late = view(14 * 60, username="bob", source_ip="10.9.9.9", outcome="success", event_type="login_success")  # 00:00 UTC
    [f] = run("SEN-AUTH-002", history + [late])
    assert len(f.evidence["reasons"]) == 2 and f.extra_points


def test_unusual_login_needs_baseline_before_flagging_new_ip():
    history = _logins(days=2)  # below min_baseline_logins (3)
    new_ip = view(0, username="bob", source_ip="10.9.9.9", outcome="success", event_type="login_success")
    assert run("SEN-AUTH-002", history + [new_ip]) == []


def test_unusual_login_respects_configured_hours():
    late = view(10 * 60, username="bob", outcome="success", event_type="login_success")  # 20:00 UTC
    assert len(run("SEN-AUTH-002", [late])) == 1
    assert run("SEN-AUTH-002", [late], ctx=DetectionContext(business_hours=(0, 24))) == []


# ---- C. privilege changes ------------------------------------------------------------------------
def _priv(minutes=0, actor="carol", target="dave", resource="group/Domain Admins", outcome="success", **kw):
    return view(minutes, event_category="privilege", event_type="group_member_added", outcome=outcome,
                username=actor, resource=resource, raw={"target_user": target}, **kw)


def test_privilege_change_approved_actor_in_hours_no_alert():
    assert run("SEN-PRIV-001", [_priv()], params={"approved_actors": ["carol"]}) == []


def test_privilege_change_non_privileged_group_no_alert():
    assert run("SEN-PRIV-001", [_priv(resource="group/Marketing")]) == []


def test_privilege_change_self_escalation_flagged():
    [f] = run("SEN-PRIV-001", [_priv(actor="dave", target="dave")], params={"approved_actors": ["dave"]})
    assert "itself" in " ".join(f.evidence["reasons"]) and f.extra_points[0]["points"] == 10


def test_privilege_change_unapproved_actor_flagged_and_failed_change_ignored():
    assert len(run("SEN-PRIV-001", [_priv()])) == 1
    assert run("SEN-PRIV-001", [_priv(outcome="failure")]) == []


# ---- D/E. access rules -------------------------------------------------------------------------
def test_restricted_access_and_allow_list():
    e = view(0, event_category="access", event_type="file_read", outcome="success", resource="/payroll/2026.csv")
    assert len(run("SEN-ACC-001", [e])) == 1
    assert run("SEN-ACC-001", [e], params={"allowed_users": ["alice"]}) == []
    normal = view(0, event_category="access", event_type="file_read", outcome="success", resource="/wiki/home")
    assert run("SEN-ACC-001", [normal]) == []


def test_failed_access_threshold_and_sensitivity():
    denied = [view(i, event_category="access", event_type="access_denied", resource="/admin/users") for i in range(3)]
    assert len(run("SEN-ACC-002", denied)) == 1
    assert run("SEN-ACC-002", denied[:2]) == []
    harmless = [view(i, event_category="access", event_type="access_denied", resource="/wiki/old") for i in range(5)]
    assert run("SEN-ACC-002", harmless) == []
    assert len(run("SEN-ACC-002", harmless, params={"sensitive_only": False})) == 1


# ---- F. reputation ------------------------------------------------------------------------------
def test_reputation_match_is_context_not_proof():
    ctx = DetectionContext(reputation={"203.0.113.5": {"verdict": "malicious", "source": "local", "confidence": 0.9}})
    [f] = run("SEN-INTEL-001", [view(0, source_ip="203.0.113.5")], ctx=ctx)
    assert "not proof" in f.description and f.severity_hint == "high"
    assert run("SEN-INTEL-001", [view(0, source_ip="203.0.113.6")], ctx=ctx) == []  # unknown IP: no alert


def test_suspicious_reputation_can_be_excluded():
    ctx = DetectionContext(reputation={"203.0.113.5": {"verdict": "suspicious", "source": "local", "confidence": 0.3}})
    assert len(run("SEN-INTEL-001", [view(0, source_ip="203.0.113.5")], ctx=ctx)) == 1
    assert run("SEN-INTEL-001", [view(0, source_ip="203.0.113.5")], ctx=ctx, params={"include_suspicious": False}) == []


# ---- G. frequency ------------------------------------------------------------------------------
def _traffic(per_bucket: list[int], system="fw-1"):
    out = []
    for bucket, n in enumerate(per_bucket):
        out += [view(bucket * 5 + i * (4.5 / max(n, 1)), source_system=system, event_category="network",
                     event_type="connection_allowed", outcome="success") for i in range(n)]
    return out


def test_frequency_steady_volume_no_alert():
    assert run("SEN-FREQ-001", _traffic([60] * 14)) == []


def test_frequency_spike_alerts_with_baseline():
    [f] = run("SEN-FREQ-001", _traffic([10] * 12 + [200]))
    assert f.evidence["baseline_median"] == 10 and f.count == 200


def test_frequency_needs_observed_history_before_alerting():
    # A system that just started logging has no baseline yet; its first busy period is not a spike.
    assert run("SEN-FREQ-001", _traffic([300, 300])) == []


def test_frequency_small_spike_below_minimum_ignored():
    assert run("SEN-FREQ-001", _traffic([1] * 12 + [40])) == []  # 40x but under min_events (50)


def test_frequency_evidence_is_capped():
    [f] = run("SEN-FREQ-001", _traffic([5] * 12 + [900]), params={"max_evidence_events": 100})
    assert len(f.events) == 100 and f.evidence["evidence_truncated"] is True


# ---- H/I/J ---------------------------------------------------------------------------------------
def test_critical_events():
    crit = view(0, severity="critical", event_category="endpoint", event_type="something_bad")
    listed = view(1, severity="high", event_category="endpoint", event_type="malware_detected")
    normal = view(2, severity="high", event_category="endpoint", event_type="scan_completed")
    [f] = run("SEN-CRIT-001", [crit, listed, normal])
    assert len(f.events) == 2 and f.severity_hint == "critical"


def test_disabled_security_controls():
    by_type = view(0, event_category="configuration", event_type="firewall_disabled")
    by_action = view(1, event_category="configuration", event_type="service_change", action="stop", resource="edr-agent")
    harmless = view(2, event_category="configuration", event_type="service_change", action="stop", resource="print-spooler")
    [f] = run("SEN-CTRL-001", [by_type, by_action, harmless])
    assert len(f.events) == 2


def test_integrity_changes_and_change_ticket_suppression():
    change = view(0, event_category="configuration", event_type="config_modified", resource="/etc/sudoers")
    ticketed = view(1, event_category="configuration", event_type="config_modified", resource="/etc/sudoers",
                    raw={"change_ticket": "CHG-1"})
    other = view(2, event_category="configuration", event_type="config_modified", resource="/etc/motd")
    [f] = run("SEN-INTEG-001", [change, ticketed, other])
    assert len(f.events) == 1
    assert len(run("SEN-INTEG-001", [ticketed], params={"ignore_with_change_ticket": False})) == 1


@pytest.mark.parametrize("rule_id", sorted(PARAMS))
def test_rules_tolerate_incomplete_events(rule_id):
    sparse = [view(i * 0.1, username=None, source_ip=None, resource=None, action=None, outcome=None,
                   event_category=c, event_type="x", severity="informational")
              for i, c in enumerate(["authentication", "access", "privilege", "configuration", "network"] * 4)]
    run(rule_id, sparse)  # must not raise


def test_high_volume_dataset_is_processed_quickly():
    events = [view(i * 0.01, username=f"u{i % 50}", source_ip=f"10.0.{i % 200}.1") for i in range(50_000)]
    start = time.perf_counter()
    findings = run("SEN-AUTH-001", events)
    assert time.perf_counter() - start < 10
    assert findings  # 50 users each with many failures


def test_findings_never_claim_confirmed_attacks():
    ctx = DetectionContext(reputation={"10.0.0.5": {"verdict": "malicious", "source": "x", "confidence": 1}})
    all_events = [view(i * 0.2) for i in range(10)] + [view(1, severity="critical", event_type="malware_detected")]
    for rule_id in RULES:
        for f in run(rule_id, all_events, ctx=ctx):
            text = (f.title + f.description).lower()
            assert "confirmed" not in text and "attack detected" not in text
    assert BASE.tzinfo is not None
