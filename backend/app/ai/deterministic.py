"""Predefined, deterministic explanations. Always available, needs no network or API key.

These are generated from the same structured context the AI would see, so the output
only ever restates stored facts and rule definitions.
"""

from app.ai.glossary import GLOSSARY

EXPECTED_FIELDS = ["username", "source_ip", "destination_ip", "resource", "action", "outcome"]


def explain_alert(ctx: dict) -> dict:
    alert, rule = ctx["alert"], ctx["rule"]
    breakdown = ctx["score_breakdown"]
    facts = [
        f"Rule {rule['id']} ({rule['name']}) matched {alert['event_count']} stored event(s) between "
        f"{alert['first_seen']} and {alert['last_seen']}.",
        f"What the rule looks for: {rule['description']}",
        f"Event types in the evidence: {', '.join(ctx['event_types']) or 'none recorded'}.",
    ]
    for key, value in ctx["evidence_summary"].items():
        if isinstance(value, (str, int, float)) or (isinstance(value, list) and len(value) <= 10):
            facts.append(f"{key.replace('_', ' ').capitalize()}: {value}")
    score_lines = [f"{item['factor']}: {item['points']:+d} ({item['explanation']})" for item in breakdown]
    missing = [f for f in EXPECTED_FIELDS if f not in ctx["fields_present"]]
    missing_info = [f"No '{f}' recorded in the evidence events." for f in missing]
    missing_info.append("Sentinel only sees the events that were ingested; activity on other systems is unknown.")
    if alert["synthetic_demo_data"]:
        facts.append("This alert was produced from synthetic demonstration data.")
    return {
        "source": "deterministic",
        "summary": f"{alert['title']}. Risk score {alert['risk_score']} ({alert['severity']}). "
                   "This is suspicious activity that requires investigation, not a confirmed attack.",
        "what_happened": facts,
        "why_flagged": rule["description"],
        "risk_score_meaning": [f"The score {alert['risk_score']} places this alert in the {alert['severity']} band "
                               "(0-19 informational, 20-39 low, 40-59 medium, 60-79 high, 80-100 critical).",
                               *score_lines],
        "facts": facts,
        "assumptions": ["None. This explanation restates stored data and the rule definition only."],
        "missing_information": missing_info,
        "recommended_steps": rule["investigation_steps"],
        "false_positive_considerations": [rule["false_positive_notes"]] if rule["false_positive_notes"] else [],
    }


def summarize_incident(ctx: dict) -> dict:
    inc = ctx["incident"]
    entities = inc["affected_entities"] or {}
    lines = [f"{inc['reference']} ({inc['status']}, {inc['severity']}, risk {inc['risk_score']}) groups "
             f"{len(ctx['alerts'])} alert(s), first detected {inc['detected_at']}."]
    for a in ctx["alerts"]:
        lines.append(f"Alert #{a['id']} [{a['rule_id']}] {a['title']}: {a['event_count']} event(s), score {a['risk_score']}, "
                     f"status {a['status']}.")
    for kind in ("accounts", "systems", "ips"):
        if entities.get(kind):
            lines.append(f"Affected {kind}: {', '.join(entities[kind][:10])}.")
    return {"source": "deterministic", "summary": " ".join(lines[:1]), "details": lines,
            "assumptions": ["None. Built from stored incident and alert records."],
            "missing_information": ["Containment actions taken outside Sentinel are not recorded unless added as notes."]}


def glossary_answer(question: str) -> dict:
    q = question.lower()
    matches = [{"term": term, "definition": text} for term, text in GLOSSARY.items()
               if term.lower() in q or any(word in q for word in term.lower().split() if len(word) > 4)]
    if not matches:
        return {"source": "deterministic", "answer": "AI assistance is not available, and the built-in glossary has no "
                "entry matching that question. Try a security term such as 'brute force', 'false positive' or "
                "'privilege escalation'.", "matches": []}
    return {"source": "deterministic", "answer": matches[0]["definition"], "matches": matches[:5]}
