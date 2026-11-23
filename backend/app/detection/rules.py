"""Detection rule logic.

Each rule is a small class with:
  * relevant(event)  - cheap filter: does this event matter to the rule?
  * lookback(params) - how much history before the evaluated period the rule needs
  * evaluate(events, params, ctx) -> list[Finding]

Rules are pure: they receive plain EventView objects and return Findings. They never
touch the database, which makes every rule independently testable with hand-built events.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta


@dataclass(frozen=True)
class EventView:
    id: int
    timestamp: datetime
    source_system: str
    event_category: str
    event_type: str
    severity: str = "informational"
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    action: str | None = None
    outcome: str | None = None
    resource: str | None = None
    description: str = ""
    raw: dict = field(default_factory=dict, hash=False, compare=False)


@dataclass
class DetectionContext:
    """Everything a rule may need besides events. Built by the engine."""

    business_hours: tuple[int, int] = (7, 19)
    # ip -> {"verdict": "malicious"|"suspicious", "source": str, "confidence": float}
    reputation: dict[str, dict] = field(default_factory=dict)

    def is_off_hours(self, ts: datetime) -> bool:
        start, end = self.business_hours
        hour = ts.astimezone(UTC).hour if ts.tzinfo else ts.hour
        return not (start <= hour < end)


@dataclass
class Finding:
    rule_id: str
    group_key: str
    events: list[EventView]
    title: str
    description: str
    evidence: dict = field(default_factory=dict)
    count: int | None = None  # observed count for threshold rules
    threshold: int | None = None
    extra_points: list[dict] = field(default_factory=list)  # rule-specific score factors
    severity_hint: str | None = None

    @property
    def event_ids(self) -> list[int]:
        return [e.id for e in self.events]

    @property
    def first_seen(self) -> datetime:
        return min(e.timestamp for e in self.events)

    @property
    def last_seen(self) -> datetime:
        return max(e.timestamp for e in self.events)

    @property
    def accounts(self) -> list[str]:
        return sorted({e.username for e in self.events if e.username})

    @property
    def ips(self) -> list[str]:
        return sorted({ip for e in self.events for ip in (e.source_ip, e.destination_ip) if ip})

    @property
    def systems(self) -> list[str]:
        return sorted({e.source_system for e in self.events})


def threshold_bursts(events: list[EventView], window: timedelta, threshold: int) -> list[list[EventView]]:
    """Greedy, deterministic windowing.

    Starting at the earliest unused event, take every event inside [start, start + window].
    If that window holds at least `threshold` events it becomes a burst and all of its events
    are consumed; otherwise move to the next event. Same input always gives the same bursts,
    which keeps repeated processing from producing different alerts.
    """
    ordered = sorted(events, key=lambda e: (e.timestamp, e.id))
    bursts: list[list[EventView]] = []
    i = 0
    while i < len(ordered):
        end_time = ordered[i].timestamp + window
        j = i
        while j < len(ordered) and ordered[j].timestamp <= end_time:
            j += 1
        if j - i >= threshold:
            bursts.append(ordered[i:j])
            i = j
        else:
            i += 1
    return bursts


def _text(event: EventView) -> str:
    """Searchable lowercase text of the fields rules match against."""
    raw_values = " ".join(str(v) for v in event.raw.values() if isinstance(v, (str, int, float)))
    return f"{event.resource or ''} {event.description} {raw_values}".lower()


def _matches_any(text: str, patterns: list[str]) -> list[str]:
    return [p for p in patterns if p and p.lower() in text]


class Rule:
    rule_id: str = ""
    categories: set[str] | None = None  # SQL prefilter; None means all categories

    def relevant(self, event: EventView, params: dict) -> bool:
        return True

    def lookback(self, params: dict) -> timedelta:
        return timedelta(minutes=params.get("window_minutes", params.get("merge_window_minutes", 60)))

    def evaluate(self, events: list[EventView], params: dict, ctx: DetectionContext) -> list[Finding]:
        raise NotImplementedError


# ---------------------------------------------------------------------------------------- A
class RepeatedAuthFailures(Rule):
    rule_id = "SEN-AUTH-001"
    categories = {"authentication"}

    def relevant(self, event, params):
        return event.event_category == "authentication" and event.outcome == "failure"

    def evaluate(self, events, params, ctx):
        threshold = int(params["threshold"])
        window = timedelta(minutes=int(params["window_minutes"]))
        spray_users = int(params.get("spray_min_distinct_users", 3))
        findings: list[Finding] = []

        by_user: dict[str, list[EventView]] = defaultdict(list)
        by_ip: dict[str, list[EventView]] = defaultdict(list)
        for e in events:
            if e.username:
                by_user[e.username].append(e)
            if e.source_ip:
                by_ip[e.source_ip].append(e)

        for username, group in sorted(by_user.items()):
            for burst in threshold_bursts(group, window, threshold):
                ips = sorted({e.source_ip for e in burst if e.source_ip})
                findings.append(Finding(
                    self.rule_id, f"username:{username}", burst,
                    f"Repeated authentication failures for {username}",
                    f"{len(burst)} failed logins for account '{username}' within {params['window_minutes']} minutes "
                    f"(threshold {threshold}). Suspicious activity detected; requires investigation.",
                    evidence={"account": username, "failures": len(burst), "source_ips": ips},
                    count=len(burst), threshold=threshold,
                ))

        # Password spraying: one source, many different accounts.
        for ip, group in sorted(by_ip.items()):
            for burst in threshold_bursts(group, window, threshold):
                users = sorted({e.username for e in burst if e.username})
                if len(users) < spray_users:
                    continue
                findings.append(Finding(
                    self.rule_id, f"source_ip:{ip}", burst,
                    f"Authentication failures across {len(users)} accounts from {ip}",
                    f"{len(burst)} failed logins against {len(users)} different accounts from {ip} within "
                    f"{params['window_minutes']} minutes. Pattern is consistent with password spraying; requires investigation.",
                    evidence={"source_ip": ip, "failures": len(burst), "accounts": users},
                    count=len(burst), threshold=threshold,
                    extra_points=[{"factor": "Multiple accounts targeted from one source", "points": 5,
                                   "explanation": f"{len(users)} distinct accounts"}],
                ))
        return findings


# ---------------------------------------------------------------------------------------- B
class UnusualLogin(Rule):
    rule_id = "SEN-AUTH-002"
    categories = {"authentication"}

    def relevant(self, event, params):
        return event.event_category == "authentication" and event.outcome == "success" and bool(event.username)

    def lookback(self, params):
        return timedelta(days=int(params["baseline_days"]))

    def evaluate(self, events, params, ctx, evaluate_from: datetime | None = None):
        min_baseline = int(params["min_baseline_logins"])
        baseline_span = timedelta(days=int(params["baseline_days"]))
        findings: list[Finding] = []
        by_user: dict[str, list[EventView]] = defaultdict(list)
        for e in events:
            by_user[e.username].append(e)

        for username, logins in sorted(by_user.items()):
            logins.sort(key=lambda e: (e.timestamp, e.id))
            for idx, login in enumerate(logins):
                if evaluate_from and login.timestamp < evaluate_from:
                    continue  # history only, used as baseline
                reasons: list[str] = []
                if params.get("check_off_hours", True) and ctx.is_off_hours(login.timestamp):
                    reasons.append(f"login at {login.timestamp.astimezone(UTC):%H:%M} UTC is outside business hours "
                                   f"({ctx.business_hours[0]:02d}:00-{ctx.business_hours[1]:02d}:00)")
                if params.get("check_new_source_ip", True) and login.source_ip:
                    baseline = [p for p in logins[:idx] if p.timestamp >= login.timestamp - baseline_span]
                    if len(baseline) >= min_baseline and login.source_ip not in {p.source_ip for p in baseline}:
                        reasons.append(f"source IP {login.source_ip} not seen in {len(baseline)} previous logins")
                if not reasons:
                    continue
                extra = []
                if len(reasons) > 1:
                    extra.append({"factor": "Several unusual characteristics", "points": 10,
                                  "explanation": "Both off-hours timing and a new source IP"})
                findings.append(Finding(
                    self.rule_id, f"username:{username}", [login],
                    f"Unusual login activity for {username}",
                    f"Successful login for '{username}' with unusual characteristics: {'; '.join(reasons)}. "
                    "Unusual authentication pattern; requires investigation.",
                    evidence={"account": username, "reasons": reasons, "source_ip": login.source_ip},
                    extra_points=extra,
                ))
        return findings


# ---------------------------------------------------------------------------------------- C
class SuspiciousPrivilegeChange(Rule):
    rule_id = "SEN-PRIV-001"
    categories = {"privilege"}

    def relevant(self, event, params):
        return event.event_category == "privilege"

    def evaluate(self, events, params, ctx):
        keywords = [k.lower() for k in params["privileged_keywords"]]
        approved = {a.lower() for a in params.get("approved_actors", [])}
        findings: list[Finding] = []
        for e in sorted(events, key=lambda x: (x.timestamp, x.id)):
            if e.outcome == "failure":
                continue
            matched = _matches_any(_text(e), keywords)
            if not matched:
                continue
            target = str(e.raw.get("target_user") or e.raw.get("target") or "").lower() or None
            reasons: list[str] = []
            if not e.username:
                reasons.append("actor is not recorded")
            elif e.username not in approved:
                reasons.append(f"actor '{e.username}' is not on the approved administrators list")
            if target and e.username and target == e.username:
                reasons.append("account granted privileges to itself")
            if params.get("flag_off_hours", True) and ctx.is_off_hours(e.timestamp):
                reasons.append(f"change made at {e.timestamp.astimezone(UTC):%H:%M} UTC, outside business hours")
            if not reasons:
                continue
            extra = [{"factor": "Self-assigned privileges", "points": 10, "explanation": "Actor and target are the same"}] \
                if "account granted privileges to itself" in reasons else []
            findings.append(Finding(
                self.rule_id, f"username:{target or e.username or 'unknown'}", [e],
                f"Suspicious privilege change{f' for {target}' if target else ''}",
                f"Privileged access ({', '.join(matched)}) was granted{f' to {target}' if target else ''} by "
                f"{e.username or 'an unknown actor'}: {'; '.join(reasons)}. Potential security incident; requires investigation.",
                evidence={"actor": e.username, "target": target, "matched_keywords": matched, "reasons": reasons},
                extra_points=extra,
            ))
        return findings


# ---------------------------------------------------------------------------------------- D
class RestrictedResourceAccess(Rule):
    rule_id = "SEN-ACC-001"
    categories = {"access", "data"}

    def relevant(self, event, params):
        return event.outcome != "failure" and bool(event.resource) and \
            bool(_matches_any((event.resource or "").lower(), params["restricted_patterns"]))

    def evaluate(self, events, params, ctx):
        allowed = {u.lower() for u in params.get("allowed_users", [])}
        window = timedelta(minutes=int(params["window_minutes"]))
        threshold = int(params.get("threshold", 1))
        by_user: dict[str, list[EventView]] = defaultdict(list)
        for e in events:
            if e.username and e.username in allowed:
                continue
            by_user[e.username or f"ip:{e.source_ip or 'unknown'}"].append(e)
        findings = []
        for who, group in sorted(by_user.items()):
            for burst in threshold_bursts(group, window, threshold):
                resources = sorted({e.resource for e in burst if e.resource})
                findings.append(Finding(
                    self.rule_id, f"username:{who}", burst,
                    f"Restricted resource accessed by {who}",
                    f"'{who}' accessed {len(resources)} restricted resource(s) without being on the allowed list: "
                    f"{', '.join(resources[:5])}. Unusual access pattern; requires investigation.",
                    evidence={"account": who, "resources": resources, "accesses": len(burst)},
                    count=len(burst), threshold=threshold,
                ))
        return findings


# ---------------------------------------------------------------------------------------- E
class MultipleFailedAccess(Rule):
    rule_id = "SEN-ACC-002"
    categories = {"access", "data"}

    def relevant(self, event, params):
        if event.outcome != "failure":
            return False
        if params.get("sensitive_only", True):
            return bool(_matches_any((event.resource or "").lower(), params["sensitive_patterns"]))
        return True

    def evaluate(self, events, params, ctx):
        threshold = int(params["threshold"])
        window = timedelta(minutes=int(params["window_minutes"]))
        groups: dict[str, list[EventView]] = defaultdict(list)
        for e in events:
            key = f"username:{e.username}" if e.username else f"source_ip:{e.source_ip or 'unknown'}"
            groups[key].append(e)
        findings = []
        for key, group in sorted(groups.items()):
            for burst in threshold_bursts(group, window, threshold):
                who = key.split(":", 1)[1]
                resources = sorted({e.resource for e in burst if e.resource})
                findings.append(Finding(
                    self.rule_id, key, burst,
                    f"Multiple failed access attempts by {who}",
                    f"{len(burst)} denied requests to sensitive resources by '{who}' within {params['window_minutes']} "
                    f"minutes (threshold {threshold}). Suspicious activity detected; requires investigation.",
                    evidence={"actor": who, "denied_requests": len(burst), "resources": resources},
                    count=len(burst), threshold=threshold,
                ))
        return findings


# ---------------------------------------------------------------------------------------- F
class SuspiciousIpReputation(Rule):
    rule_id = "SEN-INTEL-001"
    categories = None

    def relevant(self, event, params):
        return bool(event.source_ip or event.destination_ip)

    def evaluate(self, events, params, ctx):
        include_suspicious = params.get("include_suspicious", True)
        by_ip: dict[str, list[EventView]] = defaultdict(list)
        for e in events:
            for ip in (e.source_ip, e.destination_ip):
                rep = ctx.reputation.get(ip) if ip else None
                if rep and (rep["verdict"] == "malicious" or (include_suspicious and rep["verdict"] == "suspicious")):
                    by_ip[ip].append(e)
        findings = []
        for ip, group in sorted(by_ip.items()):
            rep = ctx.reputation[ip]
            findings.append(Finding(
                self.rule_id, f"ip:{ip}", sorted(set(group), key=lambda e: (e.timestamp, e.id)),
                f"Activity involving IP with {rep['verdict']} reputation ({ip})",
                f"{len(group)} event(s) involve {ip}, which {rep['source']} lists as {rep['verdict']}"
                f"{' (confidence ' + format(rep['confidence'], '.0%') + ')' if rep.get('confidence') is not None else ''}. "
                "Reputation information is context, not proof of malicious activity; requires investigation.",
                evidence={"ip": ip, "reputation": rep, "events": len(group)},
                # The verdict sets the base severity. Scoring does not add a separate reputation
                # bonus for this rule, so the same evidence is never counted twice.
                severity_hint="high" if rep["verdict"] == "malicious" else "medium",
            ))
        return findings


# ---------------------------------------------------------------------------------------- G
class UnusualEventFrequency(Rule):
    rule_id = "SEN-FREQ-001"
    categories = None

    def lookback(self, params):
        return timedelta(minutes=int(params["bucket_minutes"]) * int(params["baseline_buckets"]))

    def evaluate(self, events, params, ctx, evaluate_from: datetime | None = None):
        bucket = timedelta(minutes=int(params["bucket_minutes"]))
        n_baseline = int(params["baseline_buckets"])
        multiplier = float(params["multiplier"])
        min_events = int(params["min_events"])
        cap = int(params.get("max_evidence_events", 500))
        bucket_seconds = bucket.total_seconds()

        by_system: dict[str, dict[int, list[EventView]]] = defaultdict(lambda: defaultdict(list))
        for e in events:
            by_system[e.source_system][int(e.timestamp.timestamp() // bucket_seconds)].append(e)

        min_history = max(3, n_baseline // 2)
        findings = []
        for system, buckets in sorted(by_system.items()):
            first_index = min(buckets)
            for index in sorted(buckets):
                current = buckets[index]
                if len(current) < min_events:
                    continue
                start = datetime.fromtimestamp(index * bucket_seconds, tz=UTC)
                if evaluate_from and start + bucket < evaluate_from:
                    continue
                # Only periods after the system's first event count as history (empty periods
                # inside that span count as zero). Without enough history there is no baseline.
                history = [len(buckets.get(index - k, [])) for k in range(1, n_baseline + 1) if index - k >= first_index]
                if len(history) < min_history:
                    continue
                baseline = statistics.median(history)
                limit = multiplier * max(baseline, 1)
                if len(current) <= limit:
                    continue
                evidence_events = sorted(current, key=lambda e: (e.timestamp, e.id))[:cap]
                types: dict[str, int] = defaultdict(int)
                for e in current:
                    types[e.event_type] += 1
                top_types = sorted(types.items(), key=lambda kv: -kv[1])[:5]
                findings.append(Finding(
                    self.rule_id, f"source_system:{system}", evidence_events,
                    f"Unusual event volume from {system}",
                    f"{len(current)} events from {system} in {params['bucket_minutes']} minutes starting "
                    f"{start:%Y-%m-%d %H:%M} UTC, against a baseline median of {baseline:g} per period "
                    f"(limit {limit:g}). Requires investigation.",
                    evidence={"system": system, "count": len(current), "baseline_median": baseline,
                              "limit": limit, "top_event_types": dict(top_types),
                              "evidence_truncated": len(current) > cap},
                    count=len(current), threshold=int(limit) + 1,
                ))
        return findings


# ---------------------------------------------------------------------------------------- H
class CriticalSecurityEvent(Rule):
    rule_id = "SEN-CRIT-001"
    categories = None

    def relevant(self, event, params):
        return event.severity == "critical" or event.event_type in params["critical_event_types"]

    def evaluate(self, events, params, ctx):
        by_system: dict[str, list[EventView]] = defaultdict(list)
        for e in events:
            by_system[e.source_system].append(e)
        findings = []
        for system, group in sorted(by_system.items()):
            group.sort(key=lambda e: (e.timestamp, e.id))
            types = sorted({e.event_type for e in group})
            findings.append(Finding(
                self.rule_id, f"source_system:{system}", group,
                f"Critical security event on {system}",
                f"{len(group)} event(s) on {system} were reported as critical or match the critical list "
                f"({', '.join(types)}). Potential security incident; requires investigation.",
                evidence={"system": system, "event_types": types, "events": len(group)},
                severity_hint="critical" if any(e.severity == "critical" for e in group) else None,
            ))
        return findings


# ---------------------------------------------------------------------------------------- I
class SecurityControlDisabled(Rule):
    rule_id = "SEN-CTRL-001"
    categories = None

    def relevant(self, event, params):
        if event.event_type in params["control_event_types"]:
            return True
        action = (event.action or "").lower()
        return action in params["disabling_actions"] and \
            bool(_matches_any(f"{event.resource or ''} {event.event_type}".lower(), params["control_keywords"]))

    def evaluate(self, events, params, ctx):
        by_system: dict[str, list[EventView]] = defaultdict(list)
        for e in events:
            by_system[e.source_system].append(e)
        findings = []
        for system, group in sorted(by_system.items()):
            group.sort(key=lambda e: (e.timestamp, e.id))
            controls = sorted({e.event_type if e.event_type in params["control_event_types"] else (e.resource or e.event_type)
                               for e in group})
            actors = sorted({e.username for e in group if e.username})
            findings.append(Finding(
                self.rule_id, f"source_system:{system}", group,
                f"Security control disabled on {system}",
                f"Log records show security controls were disabled or altered on {system}: {', '.join(controls)}"
                f"{' by ' + ', '.join(actors) if actors else ''}. Requires investigation.",
                evidence={"system": system, "controls": controls, "actors": actors},
            ))
        return findings


# ---------------------------------------------------------------------------------------- J
class CriticalConfigurationChange(Rule):
    rule_id = "SEN-INTEG-001"
    categories = None

    def relevant(self, event, params):
        if event.event_type not in params["integrity_event_types"]:
            return False
        if params.get("ignore_with_change_ticket", True) and event.raw.get("change_ticket"):
            return False
        return event.event_type == "integrity_check_failed" or \
            bool(_matches_any((event.resource or "").lower(), params["critical_patterns"]))

    def evaluate(self, events, params, ctx):
        by_resource: dict[str, list[EventView]] = defaultdict(list)
        for e in events:
            by_resource[f"{e.source_system}|{e.resource or e.event_type}"].append(e)
        findings = []
        for key, group in sorted(by_resource.items()):
            system, resource = key.split("|", 1)
            group.sort(key=lambda e: (e.timestamp, e.id))
            actors = sorted({e.username for e in group if e.username})
            findings.append(Finding(
                self.rule_id, f"resource:{system}:{resource}"[:255], group,
                f"Critical configuration changed on {system}",
                f"{len(group)} change(s) to '{resource}' on {system}"
                f"{' by ' + ', '.join(actors) if actors else ''} with no recorded change ticket. "
                "Suspicious activity detected; requires investigation.",
                evidence={"system": system, "resource": resource, "actors": actors,
                          "event_types": sorted({e.event_type for e in group})},
            ))
        return findings


RULES: dict[str, Rule] = {r.rule_id: r for r in (
    RepeatedAuthFailures(), UnusualLogin(), SuspiciousPrivilegeChange(), RestrictedResourceAccess(),
    MultipleFailedAccess(), SuspiciousIpReputation(), UnusualEventFrequency(), CriticalSecurityEvent(),
    SecurityControlDisabled(), CriticalConfigurationChange(),
)}
