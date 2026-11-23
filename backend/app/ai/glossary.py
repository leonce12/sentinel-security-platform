"""Built-in educational glossary used by the AI analyst page, available offline."""

GLOSSARY: dict[str, str] = {
    "Brute force": "Trying many passwords against one account until one works. Shows up as bursts of failed logins "
                   "for the same account.",
    "Password spraying": "Trying a few common passwords against many accounts, to stay under per-account lockout "
                         "limits. Shows up as failures across several accounts from one source.",
    "False positive": "An alert raised for activity that turns out to be legitimate. Recording why it was "
                      "legitimate improves future triage.",
    "True positive": "An alert that correctly identified malicious or unauthorized activity.",
    "Privilege escalation": "Gaining more permissions than an account should have, for example adding itself to an "
                            "administrators group.",
    "Indicator of compromise": "An observable artifact (IP address, file hash, domain) associated with known "
                               "malicious activity. A match is a lead, not proof.",
    "Threat intelligence": "Information about threats and attacker infrastructure, such as reputation lists. Its "
                           "quality depends on the source and how recent it is.",
    "SIEM": "Security Information and Event Management: collects logs from many systems, normalizes them, applies "
            "detection rules and supports investigation. Sentinel is a small, educational SIEM.",
    "SOC": "Security Operations Centre: the team that monitors alerts, investigates and responds to incidents.",
    "Incident": "A security event, or group of events, that needs a coordinated response. In Sentinel an incident "
                "groups related alerts and tracks the investigation.",
    "Alert": "A notification that a detection rule matched stored events. Alerts need triage: many are benign.",
    "Risk score": "A 0-100 number that orders alerts by urgency. Sentinel's score is a documented sum of factors "
                  "multiplied by rule confidence, so every point can be explained.",
    "Anomaly detection": "Finding activity that differs from what is typical. Unusual is not the same as malicious.",
    "Isolation Forest": "A machine-learning method that isolates unusual rows by random splits. Rows that are easy "
                        "to isolate get higher anomaly scores.",
    "Normalization": "Converting logs from different sources into one common structure so they can be searched and "
                     "evaluated by the same rules.",
    "Audit log": "An append-only record of who did what and when inside an application.",
    "Lateral movement": "An attacker moving from one compromised system to others inside a network.",
    "Exfiltration": "Unauthorized transfer of data out of an organization.",
    "Containment": "Limiting the damage of an incident, for example isolating a host or disabling a compromised account.",
    "Role-based access control": "Granting permissions to roles (Administrator, SOC Analyst, ...) rather than to "
                                 "individual users, and checking them on every request.",
    "Prompt injection": "Text crafted to make an AI model ignore its instructions. Sentinel treats all log content as "
                        "untrusted data for this reason.",
}
