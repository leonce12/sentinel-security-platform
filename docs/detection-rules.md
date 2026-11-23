# Detection rules, risk scoring and anomaly detection

Detection is the foundation of Sentinel. This document specifies the ten built-in rules, how the engine applies them, how risk is scored and how the experimental anomaly model works and where it falls short. The per-rule section is generated from `backend/app/detection/definitions.py`, so it matches the defaults shipped with the code. Administrators can change thresholds, windows, lists, severity, base score, confidence and enabled state on the Detection Rules page; changes are validated (only existing parameters, same types, positive numbers) and audited.

## How the engine works

1. **Evaluated period.** After an upload the engine evaluates the time span of that job's events. A manual run evaluates every stored event or a given range.
2. **Loading.** For each enabled rule it loads events from `start - lookback` to `end + lookback`, filtered by the rule's categories in SQL. The lookback is the rule's window (or the 30-day baseline for unusual logins), so bursts and baselines that straddle the period edges are complete.
3. **Relevance and evaluation.** Each rule's `relevant()` filter keeps the events it cares about, then `evaluate()` returns findings. Rules are pure functions: they never touch the database.
4. **In-period filter.** A finding is kept only if at least one of its events lies inside the evaluated period, so old activity is not re-reported.
5. **Alerting.** For each finding, events that already back an alert of the same rule are removed. If nothing new remains the finding is "unchanged". If an alert for the same rule and group (same account, IP, system or resource) exists within the rule's window, the new events are merged into it and it is rescored; a closed alert that receives new evidence is reopened. Otherwise a new alert is created.
6. **Second pass.** Every alert touched in the run is rescored once more so the "related activity" factor does not depend on rule order, then auto-incident and correlation rules are applied.

Threshold rules use **greedy, deterministic windowing**: starting at the earliest unused event, take every event within the window; if there are at least `threshold` of them they form one burst and are consumed, otherwise move on by one event. The same input always produces the same bursts.

Wording is deliberate: findings say "suspicious activity detected", "potential security incident" or "requires investigation". The test suite checks that no finding ever claims a confirmed attack.

## Rule reference

### SEN-AUTH-001: Repeated authentication failures

| | |
|---|---|
| Category | authentication |
| Severity (default) | medium |
| Base score | 45 |
| Confidence | 80% |
| Required fields | `timestamp`, `event_category=authentication`, `outcome=failure`, `username or source_ip` |
| Parameters | `threshold` = 5, `window_minutes` = 10, `spray_min_distinct_users` = 3 |

**Detection conditions.** Many failed logins for one account within a short window, or failures across several accounts from one source address (possible password guessing or spraying).

**Why it exists.** Password guessing produces bursts of failures. A single failure is normal; a burst is not.

**Investigation steps.**

1. Check whether any login for the same account succeeded after the failures.
2. Look up the source IP: is it internal, a VPN exit, or an unfamiliar external address?
3. Ask the account owner whether they were locked out or changed their password recently.
4. Review other accounts targeted from the same source.

**False-positive considerations.** A user with an outdated saved password, a misconfigured service account, or a shared NAT address can produce the same pattern.

### SEN-AUTH-002: Unusual login activity

| | |
|---|---|
| Category | authentication |
| Severity (default) | low |
| Base score | 25 |
| Confidence | 60% |
| Required fields | `timestamp`, `event_category=authentication`, `outcome=success`, `username` |
| Parameters | `baseline_days` = 30, `min_baseline_logins` = 3, `check_off_hours` = True, `check_new_source_ip` = True, `merge_window_minutes` = 60 |

**Detection conditions.** A successful login outside configured business hours, or from a source IP the account has not used during the baseline period.

**Why it exists.** Compromised credentials are often used at unusual times or from new locations.

**Investigation steps.**

1. Confirm with the user whether they signed in at that time and from that location.
2. Check for travel, remote work or a new device.
3. Review what the session did after login.

**False-positive considerations.** Shift workers, travel, new home internet connections and VPN changes all produce new IPs or off-hours logins.

### SEN-PRIV-001: Suspicious privilege change

| | |
|---|---|
| Category | privilege |
| Severity (default) | high |
| Base score | 60 |
| Confidence | 75% |
| Required fields | `timestamp`, `event_category=privilege`, `username (actor)`, `resource or raw.new_role (privilege granted)` |
| Parameters | `privileged_keywords` = [admin, administrator, domain admins, root, sudo, superuser], `approved_actors` = [] (empty), `flag_off_hours` = True, `merge_window_minutes` = 60 |

**Detection conditions.** Administrative privileges granted by an actor who is not on the approved list, outside business hours, or by an account to itself.

**Why it exists.** Attackers who gain a foothold often grant themselves or a new account administrative rights.

**Investigation steps.**

1. Find the change request or ticket that authorizes the change.
2. Verify the actor's identity and whether their own account shows other unusual activity.
3. Check what the newly privileged account did afterwards.

**False-positive considerations.** Legitimate onboarding or emergency changes. Add regular administrators to approved_actors to reduce noise.

### SEN-ACC-001: Access to restricted resource

| | |
|---|---|
| Category | access |
| Severity (default) | medium |
| Base score | 45 |
| Confidence | 65% |
| Required fields | `timestamp`, `event_category=access`, `resource`, `username` |
| Parameters | `restricted_patterns` = [/admin, /etc/shadow, payroll, hr/records, secrets, /backup, finance/ledger], `allowed_users` = [] (empty), `threshold` = 1, `window_minutes` = 60 |

**Detection conditions.** Successful access to a resource marked as restricted by a user who is not on the allowed list.

**Why it exists.** Restricted data (payroll, secrets, backups) should only be read by a small, known group.

**Investigation steps.**

1. Confirm whether the user's job requires this access.
2. Check how the user obtained the permission.
3. Review the volume of data accessed.

**False-positive considerations.** New team members, auditors and service accounts may be legitimate. Maintain allowed_users.

### SEN-ACC-002: Multiple failed access attempts

| | |
|---|---|
| Category | access |
| Severity (default) | medium |
| Base score | 45 |
| Confidence | 75% |
| Required fields | `timestamp`, `event_category=access`, `outcome=failure`, `resource`, `username or source_ip` |
| Parameters | `threshold` = 3, `window_minutes` = 15, `sensitive_patterns` = [/admin, /etc/shadow, payroll, hr/records, secrets, /backup, finance/ledger], `sensitive_only` = True |

**Detection conditions.** Repeated authorization failures against sensitive resources by one account or source.

**Why it exists.** Probing for resources an account cannot reach is typical of reconnaissance.

**Investigation steps.**

1. List the resources the account tried to reach.
2. Check whether the account recently changed role or lost access.
3. Look for successful access to similar resources afterwards.

**False-positive considerations.** Broken bookmarks, scripts with stale paths and recent permission changes.

### SEN-INTEL-001: IP address with poor reputation

| | |
|---|---|
| Category | network |
| Severity (default) | medium |
| Base score | 45 |
| Confidence | 60% |
| Required fields | `timestamp`, `source_ip or destination_ip` |
| Parameters | `include_suspicious` = True, `merge_window_minutes` = 60 |

**Detection conditions.** An event involves an IP address that threat intelligence lists as malicious or suspicious. Reputation is context, not proof of malicious activity.

**Why it exists.** Known bad infrastructure is a useful signal when combined with other evidence.

**Investigation steps.**

1. Review the intelligence source, its date and its confidence.
2. Check what the IP did: was the connection allowed or blocked, did a login succeed?
3. Search for other events involving the same IP.

**False-positive considerations.** Reputation lists contain stale entries, shared hosting and VPN or cloud addresses that are reassigned.

### SEN-FREQ-001: Unusual event frequency

| | |
|---|---|
| Category | system |
| Severity (default) | medium |
| Base score | 45 |
| Confidence | 50% |
| Required fields | `timestamp`, `source_system` |
| Parameters | `bucket_minutes` = 5, `baseline_buckets` = 12, `multiplier` = 3.0, `min_events` = 50, `max_evidence_events` = 500 |

**Detection conditions.** A source system produced far more events in a short period than its recent baseline.

**Why it exists.** Sudden volume spikes can indicate scanning, brute force, malware activity or a failing system.

**Investigation steps.**

1. Break the spike down by event type to see what is driving it.
2. Check for scheduled jobs, deployments or backups at that time.
3. Review whether related alerts were raised for the same system.

**False-positive considerations.** Batch jobs, deployments, log replays and misconfigured logging produce spikes.

### SEN-CRIT-001: Critical security event reported

| | |
|---|---|
| Category | endpoint |
| Severity (default) | high |
| Base score | 60 |
| Confidence | 85% |
| Required fields | `timestamp`, `severity or event_type` |
| Parameters | `critical_event_types` = [malware_detected, ransomware_activity, intrusion_detected, data_exfiltration_suspected, credential_dumping_detected], `merge_window_minutes` = 60 |

**Detection conditions.** A trusted source reported an event as critical, or the event type is on the configured critical list (for example malware detection).

**Why it exists.** Security tools that already assessed an event as critical deserve fast human review.

**Investigation steps.**

1. Read the original tool output in the raw event data.
2. Determine whether the threat was blocked or is still active.
3. Identify the affected host and account and decide on containment.

**False-positive considerations.** Test signatures (such as EICAR files) and tool misconfiguration.

### SEN-CTRL-001: Security control disabled

| | |
|---|---|
| Category | configuration |
| Severity (default) | high |
| Base score | 60 |
| Confidence | 80% |
| Required fields | `timestamp`, `event_type, or action plus resource` |
| Parameters | `control_event_types` = [antivirus_disabled, firewall_disabled, audit_logging_disabled, audit_log_cleared, edr_agent_stopped, security_control_disabled, mfa_disabled], `control_keywords` = [antivirus, firewall, audit, edr, defender, mfa, logging], `disabling_actions` = [disable, disabled, stop, stopped, delete, clear, uninstall], `merge_window_minutes` = 60 |

**Detection conditions.** A log record shows that a security control (antivirus, firewall, audit logging, MFA, EDR) was disabled, stopped or cleared.

**Why it exists.** Disabling defenses is a common step before or after an intrusion.

**Investigation steps.**

1. Identify who made the change and whether it was planned maintenance.
2. Re-enable the control if the change was not authorized.
3. Review activity on the host during the period the control was off.

**False-positive considerations.** Planned maintenance, troubleshooting and software upgrades.

### SEN-INTEG-001: Change to critical configuration

| | |
|---|---|
| Category | data |
| Severity (default) | medium |
| Base score | 45 |
| Confidence | 70% |
| Required fields | `timestamp`, `event_type`, `resource` |
| Parameters | `integrity_event_types` = [config_modified, file_integrity_violation, record_modified, record_deleted, policy_modified, integrity_check_failed], `critical_patterns` = [/etc/passwd, /etc/sudoers, security_policy, detection_rules, firewall_rules, audit_config, currentversion\run], `ignore_with_change_ticket` = True, `merge_window_minutes` = 60 |

**Detection conditions.** A modification or deletion of an important security or configuration record without a recorded change ticket.

**Why it exists.** Tampering with security configuration can hide activity or create persistence.

**Investigation steps.**

1. Compare the old and new values if the source recorded them.
2. Find the change ticket or the person responsible.
3. Restore from a known-good copy if the change was not authorized.

**False-positive considerations.** Configuration management tools and routine updates. Recording a change_ticket field in the source log suppresses the alert by default.

## Risk scoring

Implemented in `backend/app/scoring/engine.py`. Every alert stores the list of factors below with points and a plain-language explanation; the alert page shows the table and the final score.

```
subtotal = base + frequency + accounts + reputation + asset + rule_context + related      (capped to 0..100)
score    = round(subtotal × (0.6 + 0.4 × rule_confidence))
```

| Factor | Points | Notes |
|--------|--------|-------|
| Rule base score | Configured per rule; defaults 10 / 25 / 45 / 60 / 75 for informational to critical | Raised to the base of a higher severity when the rule's evidence indicates it (for example a malicious reputation verdict, or a source that reported the event as critical) |
| Event frequency | `5 × log2(count / threshold)`, max 15 | Threshold rules only; logarithmic so 1,000 events do not dwarf 20 |
| Affected accounts | 4 per account beyond the first, max 10 | Distinct usernames in the evidence |
| Source reputation | +15 malicious, +7 suspicious | Strongest single IP only, counted once. Skipped for SEN-INTEL-001, whose base already reflects the verdict |
| Asset importance | +10 high, +5 medium | From Settings > Asset importance, most important system only |
| Rule-specific context | Supplied by the rule, max 15 in total | e.g. self-assigned privileges +10, spraying across many accounts +5, several unusual login traits +10 |
| Related activity | +5 per other open alert on the same account or IP in the previous 24 h, max 10 | Alerts that share evidence events are excluded |
| Detection confidence | Multiplier 0.6 to 1.0 | Confidence 1.0 keeps the subtotal; 0.5 reduces it by 20% |

Severity bands: 0 to 19 informational, 20 to 39 low, 40 to 59 medium, 60 to 79 high, 80 to 100 critical. An alert's severity follows its score.

**Avoiding double counting.** Each factor reads a different property of the evidence; reputation is applied once for the strongest IP; related alerts that share evidence are excluded; incident risk is the maximum, never the sum, of its alerts; and an event's risk score is the highest score of any alert that uses it.

**Recalculation.** Scores are recalculated when evidence is merged into an alert, in the second pass of every run and on demand ("Recalculate score", for example after adding a threat indicator). Every change is written to the alert history and, for evidence-driven or manual changes, to the audit log.

**Limitations.** Points and weights are expert judgement, not fitted to data. Related-activity points are only computed when an alert is scored, so an older alert does not gain points when a later related alert appears unless it is rescored. Asset importance must be maintained by hand.

**Automatic incidents.** When an alert reaches the configured minimum (default 80) an incident is created, unless an open, automatically created incident already involves the same account or IP within 24 hours, in which case the alert is attached to it. When an incident is created, open alerts sharing an account or IP within 24 hours are linked to it as related evidence. In the demo this groups the six alerts about the `nora.b` account into one incident.

## Anomaly detection (experimental)

Implemented in `backend/app/anomaly/service.py`, disabled by default.

- **Unit of analysis:** one row per account per hour over the last 30 days of stored events.
- **Features:** `event_count`, `auth_failures`, `auth_successes`, `distinct_source_ips`, `distinct_resources`, `access_denied`, `off_hours`.
- **Pipeline:** median imputation for missing values, standard scaling, Isolation Forest (200 trees, fixed random seed, contamination from Settings, default 0.05).
- **Score:** the model's anomaly score rescaled to 0..1 for display.
- **Explanation:** features whose value is more than two standard deviations from the mean of all rows, with the observed value and the typical value.
- **Review:** analysts mark each result as needing follow-up or as a false positive with a note. Reviewed results survive later runs.
- **Separation:** results never create alerts, never change risk scores and never create incidents.

**Evaluation methodology.** The test suite builds ten days of regular activity for eight accounts and injects one hour with 40 failed logins from 40 addresses for one account. The test asserts that this account-hour is the top-ranked result, that its explanation names the injected features and that no alert is created. On the demo dataset (421 account-hours, contamination 0.05) the run flagged 20 hours. The highest-ranked was the `nora.b` brute-force hour (auth failures, off hours, event count), second was `brian.o`'s night-time probing (access denied, off hours, distinct resources) and fifth was `chen.l`'s late login; several others were ordinary busy hours, which shows why results need review. This is a sanity check, not a performance measurement: there is no labelled dataset, so precision and recall are unknown.

**Limitations.** The model is retrained on every run and not persisted. Contamination is an assumption, not a measurement, so the model always flags roughly that share of rows. Accounts with little history look unusual. Unusual is not malicious; the model does not detect attacks, it points at hours worth a look. It needs at least 50 account-hours of data.
