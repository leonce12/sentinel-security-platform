"""Default definitions for the ten built-in detection rules.

These are seeded into the detection_rules table. Administrators can then change
thresholds, windows, severity, confidence and lists from the Rules page; the logic
in rules.py reads the stored parameters, never these defaults directly.
"""

SEVERITY_BASE_SCORE = {"informational": 10, "low": 25, "medium": 45, "high": 60, "critical": 75}

RESTRICTED_PATTERNS = ["/admin", "/etc/shadow", "payroll", "hr/records", "secrets", "/backup", "finance/ledger"]

RULE_DEFINITIONS: list[dict] = [
    {
        "id": "SEN-AUTH-001",
        "name": "Repeated authentication failures",
        "category": "authentication",
        "severity": "medium",
        "confidence": 0.8,
        "description": "Many failed logins for one account within a short window, or failures across several "
                       "accounts from one source address (possible password guessing or spraying).",
        "required_fields": ["timestamp", "event_category=authentication", "outcome=failure",
                            "username or source_ip"],
        "parameters": {"threshold": 5, "window_minutes": 10, "spray_min_distinct_users": 3},
        "rationale": "Password guessing produces bursts of failures. A single failure is normal; a burst is not.",
        "investigation_steps": [
            "Check whether any login for the same account succeeded after the failures.",
            "Look up the source IP: is it internal, a VPN exit, or an unfamiliar external address?",
            "Ask the account owner whether they were locked out or changed their password recently.",
            "Review other accounts targeted from the same source.",
        ],
        "false_positive_notes": "A user with an outdated saved password, a misconfigured service account, or a "
                                "shared NAT address can produce the same pattern.",
    },
    {
        "id": "SEN-AUTH-002",
        "name": "Unusual login activity",
        "category": "authentication",
        "severity": "low",
        "confidence": 0.6,
        "description": "A successful login outside configured business hours, or from a source IP the account "
                       "has not used during the baseline period.",
        "required_fields": ["timestamp", "event_category=authentication", "outcome=success", "username"],
        "parameters": {"baseline_days": 30, "min_baseline_logins": 3, "check_off_hours": True,
                       "check_new_source_ip": True, "merge_window_minutes": 60},
        "rationale": "Compromised credentials are often used at unusual times or from new locations.",
        "investigation_steps": [
            "Confirm with the user whether they signed in at that time and from that location.",
            "Check for travel, remote work or a new device.",
            "Review what the session did after login.",
        ],
        "false_positive_notes": "Shift workers, travel, new home internet connections and VPN changes all "
                                "produce new IPs or off-hours logins.",
    },
    {
        "id": "SEN-PRIV-001",
        "name": "Suspicious privilege change",
        "category": "privilege",
        "severity": "high",
        "confidence": 0.75,
        "description": "Administrative privileges granted by an actor who is not on the approved list, outside "
                       "business hours, or by an account to itself.",
        "required_fields": ["timestamp", "event_category=privilege", "username (actor)",
                            "resource or raw.new_role (privilege granted)"],
        "parameters": {"privileged_keywords": ["admin", "administrator", "domain admins", "root", "sudo", "superuser"],
                       "approved_actors": [], "flag_off_hours": True, "merge_window_minutes": 60},
        "rationale": "Attackers who gain a foothold often grant themselves or a new account administrative rights.",
        "investigation_steps": [
            "Find the change request or ticket that authorizes the change.",
            "Verify the actor's identity and whether their own account shows other unusual activity.",
            "Check what the newly privileged account did afterwards.",
        ],
        "false_positive_notes": "Legitimate onboarding or emergency changes. Add regular administrators to "
                                "approved_actors to reduce noise.",
    },
    {
        "id": "SEN-ACC-001",
        "name": "Access to restricted resource",
        "category": "access",
        "severity": "medium",
        "confidence": 0.65,
        "description": "Successful access to a resource marked as restricted by a user who is not on the "
                       "allowed list.",
        "required_fields": ["timestamp", "event_category=access", "resource", "username"],
        "parameters": {"restricted_patterns": RESTRICTED_PATTERNS, "allowed_users": [], "threshold": 1,
                       "window_minutes": 60},
        "rationale": "Restricted data (payroll, secrets, backups) should only be read by a small, known group.",
        "investigation_steps": [
            "Confirm whether the user's job requires this access.",
            "Check how the user obtained the permission.",
            "Review the volume of data accessed.",
        ],
        "false_positive_notes": "New team members, auditors and service accounts may be legitimate. Maintain "
                                "allowed_users.",
    },
    {
        "id": "SEN-ACC-002",
        "name": "Multiple failed access attempts",
        "category": "access",
        "severity": "medium",
        "confidence": 0.75,
        "description": "Repeated authorization failures against sensitive resources by one account or source.",
        "required_fields": ["timestamp", "event_category=access", "outcome=failure", "resource",
                            "username or source_ip"],
        "parameters": {"threshold": 3, "window_minutes": 15, "sensitive_patterns": RESTRICTED_PATTERNS,
                       "sensitive_only": True},
        "rationale": "Probing for resources an account cannot reach is typical of reconnaissance.",
        "investigation_steps": [
            "List the resources the account tried to reach.",
            "Check whether the account recently changed role or lost access.",
            "Look for successful access to similar resources afterwards.",
        ],
        "false_positive_notes": "Broken bookmarks, scripts with stale paths and recent permission changes.",
    },
    {
        "id": "SEN-INTEL-001",
        "name": "IP address with poor reputation",
        "category": "network",
        "severity": "medium",
        "confidence": 0.6,
        "description": "An event involves an IP address that threat intelligence lists as malicious or "
                       "suspicious. Reputation is context, not proof of malicious activity.",
        "required_fields": ["timestamp", "source_ip or destination_ip"],
        "parameters": {"include_suspicious": True, "merge_window_minutes": 60},
        "rationale": "Known bad infrastructure is a useful signal when combined with other evidence.",
        "investigation_steps": [
            "Review the intelligence source, its date and its confidence.",
            "Check what the IP did: was the connection allowed or blocked, did a login succeed?",
            "Search for other events involving the same IP.",
        ],
        "false_positive_notes": "Reputation lists contain stale entries, shared hosting and VPN or cloud "
                                "addresses that are reassigned.",
    },
    {
        "id": "SEN-FREQ-001",
        "name": "Unusual event frequency",
        "category": "system",
        "severity": "medium",
        "confidence": 0.5,
        "description": "A source system produced far more events in a short period than its recent baseline.",
        "required_fields": ["timestamp", "source_system"],
        "parameters": {"bucket_minutes": 5, "baseline_buckets": 12, "multiplier": 3.0, "min_events": 50,
                       "max_evidence_events": 500},
        "rationale": "Sudden volume spikes can indicate scanning, brute force, malware activity or a failing system.",
        "investigation_steps": [
            "Break the spike down by event type to see what is driving it.",
            "Check for scheduled jobs, deployments or backups at that time.",
            "Review whether related alerts were raised for the same system.",
        ],
        "false_positive_notes": "Batch jobs, deployments, log replays and misconfigured logging produce spikes.",
    },
    {
        "id": "SEN-CRIT-001",
        "name": "Critical security event reported",
        "category": "endpoint",
        "severity": "high",
        "confidence": 0.85,
        "description": "A trusted source reported an event as critical, or the event type is on the configured "
                       "critical list (for example malware detection).",
        "required_fields": ["timestamp", "severity or event_type"],
        "parameters": {"critical_event_types": ["malware_detected", "ransomware_activity", "intrusion_detected",
                                                "data_exfiltration_suspected", "credential_dumping_detected"],
                       "merge_window_minutes": 60},
        "rationale": "Security tools that already assessed an event as critical deserve fast human review.",
        "investigation_steps": [
            "Read the original tool output in the raw event data.",
            "Determine whether the threat was blocked or is still active.",
            "Identify the affected host and account and decide on containment.",
        ],
        "false_positive_notes": "Test signatures (such as EICAR files) and tool misconfiguration.",
    },
    {
        "id": "SEN-CTRL-001",
        "name": "Security control disabled",
        "category": "configuration",
        "severity": "high",
        "confidence": 0.8,
        "description": "A log record shows that a security control (antivirus, firewall, audit logging, MFA, EDR) "
                       "was disabled, stopped or cleared.",
        "required_fields": ["timestamp", "event_type, or action plus resource"],
        "parameters": {"control_event_types": ["antivirus_disabled", "firewall_disabled", "audit_logging_disabled",
                                               "audit_log_cleared", "edr_agent_stopped", "security_control_disabled",
                                               "mfa_disabled"],
                       "control_keywords": ["antivirus", "firewall", "audit", "edr", "defender", "mfa", "logging"],
                       "disabling_actions": ["disable", "disabled", "stop", "stopped", "delete", "clear", "uninstall"],
                       "merge_window_minutes": 60},
        "rationale": "Disabling defenses is a common step before or after an intrusion.",
        "investigation_steps": [
            "Identify who made the change and whether it was planned maintenance.",
            "Re-enable the control if the change was not authorized.",
            "Review activity on the host during the period the control was off.",
        ],
        "false_positive_notes": "Planned maintenance, troubleshooting and software upgrades.",
    },
    {
        "id": "SEN-INTEG-001",
        "name": "Change to critical configuration",
        "category": "data",
        "severity": "medium",
        "confidence": 0.7,
        "description": "A modification or deletion of an important security or configuration record without a "
                       "recorded change ticket.",
        "required_fields": ["timestamp", "event_type", "resource"],
        "parameters": {"integrity_event_types": ["config_modified", "file_integrity_violation", "record_modified",
                                                 "record_deleted", "policy_modified", "integrity_check_failed"],
                       "critical_patterns": ["/etc/passwd", "/etc/sudoers", "security_policy", "detection_rules",
                                             "firewall_rules", "audit_config", "currentversion\\run"],
                       "ignore_with_change_ticket": True, "merge_window_minutes": 60},
        "rationale": "Tampering with security configuration can hide activity or create persistence.",
        "investigation_steps": [
            "Compare the old and new values if the source recorded them.",
            "Find the change ticket or the person responsible.",
            "Restore from a known-good copy if the change was not authorized.",
        ],
        "false_positive_notes": "Configuration management tools and routine updates. Recording a change_ticket "
                                "field in the source log suppresses the alert by default.",
    },
]


def default_rule_rows() -> list[dict]:
    rows = []
    for definition in RULE_DEFINITIONS:
        row = dict(definition)
        row["base_score"] = SEVERITY_BASE_SCORE[definition["severity"]]
        rows.append(row)
    return rows
