# User guide

This guide walks through Sentinel screen by screen. What you see depends on your role; the backend enforces the same rules, so a hidden button is never the only protection.

| Role | Can do |
|------|--------|
| **Administrator** | Everything, including users, API keys, rules, settings, audit logs and demo data |
| **SOC Analyst** | Ingest and export events, triage and manage alerts, manage incidents, run detection and anomaly detection, threat lookups, AI analyst, reports |
| **IT Administrator** | Ingest and export events, acknowledge and annotate alerts, view incidents, threat lookups, AI analyst, reports |
| **Read-Only Viewer** | View the dashboard, events, alerts, incidents, rules and reports |

## First sign-in

An administrator is created from the command line (`python -m app.cli create-admin`). Sign in at the login page; after five wrong passwords an account is locked for 15 minutes. Your session refreshes automatically; signing out or changing your password ends it everywhere.

## Overview (dashboard)

Eight statistic tiles, eight charts and a recent activity table, all computed from the database when you open the page and refreshed every minute.

- **Date range**: by default the 7 days ending at the newest stored event (useful for historical datasets). Choose 24 hours, 7 or 30 days, or a custom UTC range.
- **Tiles** link to filtered lists, for example "High-risk events" opens events with risk 60 or more.
- **Recent activity** supports search, severity and category filters, sortable columns and pagination; click a row for the event detail.
- A dashed banner tells you how many events in the range are synthetic.

## Security Events

- **Upload logs**: choose a CSV, JSON or NDJSON file, optionally mark it as synthetic, and choose whether to run detection. The summary shows records received, stored, rejected (with the reason for each) and duplicates, and the detection result.
- **Submit event**: a form for a single event, handy for testing a rule.
- **Filters**: text search, severity, category, source, event type, time range, username, IP, minimum risk and "alert evidence only". Filters live in the URL, so a filtered view can be bookmarked.
- **Export CSV / JSON** exports exactly the filtered events (up to 50,000).
- **Ingestion jobs** tab: history of uploads with their summaries.
- **Event detail**: normalized fields, the alerts that use the event as evidence, related incidents and the raw original record (shown as text).

## Alerts

Each alert comes from one rule and links to the stored events that caused it.

- **Acknowledge** to show you have seen it (also available to IT administrators).
- **Set investigating / resolved**, **Mark false positive** (a reason of at least 10 characters is required), **Reopen**.
- **Assign** to an administrator or SOC analyst; they get a notification.
- **Why this score**: every factor with its points and explanation.
- **Investigation guidance**: the rule's recommended steps and known false positives.
- **Convert to incident**, either as a new incident or added to an open one.
- **Recalculate score** after adding threat intelligence or changing asset importance.

A false-positive decision applies to the evidence reviewed. If new evidence arrives for the same activity the alert reopens, so an important event is never silently suppressed.

## Incidents

Incidents group related alerts. High-risk alerts (score 80 or more by default) create incidents automatically and pull in other open alerts about the same account or IP.

- Status workflow: Open, Investigating, Contained, Resolved, Closed. Resolving or closing needs resolution details; reopening a closed incident needs a reason.
- Assign an analyst, add investigation notes and review the timeline of every change.
- **Incident report (PDF)** downloads a report with the overview, entities, alerts, score factors, evidence, timeline, notes and resolution.
- Incidents cannot be deleted.

## Threat Intelligence

- **Lookup** an IP against the local dataset and, if enabled, VirusTotal. Each result shows the provider, time, verdict, confidence and limitations. "No information" and "No detections" do not mean an address is safe.
- **Local indicators**: the offline list used by the reputation rule and scoring. Administrators can add entries.
- **Lookup history** of all checks.

## Detection Rules

- Expand a rule to read its conditions, parameters, required fields, investigation steps and false-positive notes.
- **Configure** (administrators): enable or disable, severity, base score, confidence and every parameter. Changes are audited.
- **Run on all stored events** re-runs detection; it is safe to repeat.
- **Anomaly detection (experimental)** tab: run the model when enabled in Settings, read why each account-hour stands out and record a review.

## AI Security Analyst

Explains alerts, summarizes incidents and answers learning questions. Without an AI provider it still gives a built-in explanation from the stored data and rule definitions, and a glossary of security terms. When AI is enabled, its answer is shown next to the built-in one and labelled "verify before acting". It cannot change any record.

## Reports

Generate daily, weekly or incident PDF reports. Each is generated from current database records and stored with its SHA-256 hash, so a copy can be checked later.

## Notifications

In-app only: critical alerts, high-risk incidents, assignments, status changes on your incidents and failed ingestion jobs. Click one to open the related page.

## Audit Logs (administrators)

Every sign-in, denied request, administrative change and analyst action, with outcome and details. Search, filter by outcome and export to CSV. Entries cannot be changed or deleted.

## User Management (administrators)

Create users, change roles, deactivate accounts, reset passwords (which signs the user out everywhere), review role permissions and manage ingestion API keys (shown once at creation).

## Settings (administrators)

Detection automation and the auto-incident threshold, business hours (UTC) used by the unusual login and privilege rules, asset importance for scoring, optional services (VirusTotal, AI, anomaly detection), self-registration, and demonstration data load and reset.

## Profile

Update your name and email, change your password and see your permissions.
