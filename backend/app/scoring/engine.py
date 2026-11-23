"""Transparent risk scoring.

score = round(clamp(subtotal, 0, 100) * confidence_multiplier)

subtotal is the sum of these factors, each recorded with its reason:

  1. Rule base score            configured per rule (default from severity: 10/25/45/60/75)
                                raised to the severity hint's base when a rule supplies one
  2. Event frequency            +5 * log2(count / threshold), max +15 (threshold rules only)
  3. Affected accounts          +4 per account beyond the first, max +10
  4. Source reputation          +15 malicious, +7 suspicious, strongest IP only, once
                                (skipped for SEN-INTEL-001, whose base already reflects it)
  5. Asset importance           +10 high, +5 medium (most important system only)
  6. Rule-specific context      points supplied by the rule, max +15 in total
  7. Related activity           +5 per other open alert on the same account or IP in the
                                previous 24 hours that shares no evidence events, max +10

confidence_multiplier = 0.6 + 0.4 * rule_confidence  (confidence 1.0 keeps the score,
confidence 0.5 reduces it by 20%)

Each factor uses distinct evidence, so one piece of evidence never inflates the score
twice. No AI model is involved: the AI analyst may explain a score but cannot set one.
"""

import math
from dataclasses import dataclass, field

from app.detection.definitions import SEVERITY_BASE_SCORE

REPUTATION_POINTS = {"malicious": 15, "suspicious": 7}
ASSET_POINTS = {"high": 10, "medium": 5, "low": 0}


def severity_for_score(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "informational"


@dataclass
class ScoreInput:
    rule_id: str
    base_score: int
    confidence: float
    count: int | None = None
    threshold: int | None = None
    accounts: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    systems: list[str] = field(default_factory=list)
    severity_hint: str | None = None
    extra_points: list[dict] = field(default_factory=list)
    related_alert_ids: list[int] = field(default_factory=list)


@dataclass
class ScoreResult:
    score: int
    severity: str
    breakdown: list[dict]


def calculate(inp: ScoreInput, reputation: dict[str, dict], asset_criticality: dict[str, str]) -> ScoreResult:
    breakdown: list[dict] = []

    base = inp.base_score
    explanation = f"Configured base score for rule {inp.rule_id}"
    if inp.severity_hint and SEVERITY_BASE_SCORE.get(inp.severity_hint, 0) > base:
        base = SEVERITY_BASE_SCORE[inp.severity_hint]
        explanation = f"Base score for {inp.severity_hint} severity indicated by the rule's evidence"
    breakdown.append({"factor": "Rule base score", "points": base, "explanation": explanation})

    if inp.count and inp.threshold and inp.count > inp.threshold:
        ratio = inp.count / inp.threshold
        points = min(15, round(5 * math.log2(ratio)))
        if points:
            breakdown.append({"factor": "Event frequency", "points": points,
                              "explanation": f"{inp.count} events against a threshold of {inp.threshold} ({ratio:.1f}x)"})

    if len(inp.accounts) > 1:
        points = min(10, 4 * (len(inp.accounts) - 1))
        breakdown.append({"factor": "Affected accounts", "points": points,
                          "explanation": f"{len(inp.accounts)} accounts involved"})

    if inp.rule_id != "SEN-INTEL-001":
        worst = None
        for ip in inp.ips:
            rep = reputation.get(ip)
            if rep and (worst is None or REPUTATION_POINTS.get(rep["verdict"], 0) > REPUTATION_POINTS.get(worst[1]["verdict"], 0)):
                worst = (ip, rep)
        if worst and REPUTATION_POINTS.get(worst[1]["verdict"]):
            breakdown.append({"factor": "Source reputation", "points": REPUTATION_POINTS[worst[1]["verdict"]],
                              "explanation": f"{worst[0]} is listed as {worst[1]['verdict']} by {worst[1]['source']} "
                                             "(context, not proof)"})

    levels = [(asset_criticality.get(s), s) for s in inp.systems if asset_criticality.get(s)]
    if levels:
        level, system = max(levels, key=lambda pair: ASSET_POINTS.get(pair[0], 0))
        if ASSET_POINTS.get(level):
            breakdown.append({"factor": "Asset importance", "points": ASSET_POINTS[level],
                              "explanation": f"{system} is configured as {level} importance"})

    extra_total = 0
    for extra in inp.extra_points:
        points = max(0, min(int(extra["points"]), 15 - extra_total))
        if points:
            extra_total += points
            breakdown.append({"factor": extra["factor"], "points": points, "explanation": extra["explanation"]})

    if inp.related_alert_ids:
        points = min(10, 5 * len(inp.related_alert_ids))
        breakdown.append({"factor": "Related activity", "points": points,
                          "explanation": f"{len(inp.related_alert_ids)} other open alert(s) on the same account or IP "
                                         f"in the previous 24 hours: {', '.join(f'#{i}' for i in inp.related_alert_ids[:5])}"})

    subtotal = min(100, max(0, sum(item["points"] for item in breakdown)))
    multiplier = 0.6 + 0.4 * max(0.0, min(1.0, inp.confidence))
    score = int(round(subtotal * multiplier))
    breakdown.append({"factor": "Detection confidence", "points": score - subtotal,
                      "explanation": f"Rule confidence {inp.confidence:.0%} gives multiplier {multiplier:.2f} "
                                     f"applied to subtotal {subtotal}"})
    return ScoreResult(score=score, severity=severity_for_score(score), breakdown=breakdown)
