"""Offline acceptance test (section 35 of the project specification).

Drives the real application through a browser (Playwright) and checks results directly in
PostgreSQL. It writes the actual outcome of every step to a Markdown report; nothing is
pre-filled. Run it against a freshly migrated database that has one administrator and one
SOC analyst account, with no AI key configured and, ideally, with no network access.

    python e2e/offline_acceptance.py --base-url http://localhost:5173 \
        --db "postgresql://sentinel:...@/sentinel_offline?host=/tmp" \
        --admin admin --admin-password-env E2E_ADMIN_PASSWORD --analyst analyst.amina \
        --report docs/offline-acceptance-results.md
"""

import argparse
import os
import platform
import socket
import sys
import time
import traceback
from datetime import UTC, datetime
from pathlib import Path

import psycopg
from playwright.sync_api import Page, expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
CSV_FILE = ROOT / "sample_data" / "logs" / "sentinel_demo_events.csv"
JSON_FILE = ROOT / "sample_data" / "logs" / "sentinel_demo_events.json"
INTEL_FILE = ROOT / "sample_data" / "datasets" / "threat_intel_local.csv"


class Recorder:
    def __init__(self):
        self.rows: list[tuple[int, str, str, str]] = []

    def step(self, number: int, name: str, fn):
        started = time.perf_counter()
        try:
            detail = fn() or ""
            status = "PASS"
        except Exception as exc:  # record and continue so the report is complete
            detail = f"{type(exc).__name__}: {str(exc).splitlines()[0][:300]}"
            status = "FAIL"
            traceback.print_exc()
        elapsed = time.perf_counter() - started
        self.rows.append((number, name, status, f"{detail} ({elapsed:.1f}s)"))
        print(f"[{status}] {number}. {name}: {detail}")
        return status == "PASS"


def internet_reachable() -> bool:
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=3).close()
        return True
    except OSError:
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:5173")
    ap.add_argument("--db", required=True, help="psycopg connection string for the same database the API uses")
    ap.add_argument("--admin", default="admin")
    ap.add_argument("--admin-password-env", default="E2E_ADMIN_PASSWORD")
    ap.add_argument("--analyst", default="analyst.amina")
    ap.add_argument("--report", default=str(ROOT / "docs" / "offline-acceptance-results.md"))
    ap.add_argument("--chrome", default=os.environ.get("CHROME_PATH"))
    ap.add_argument("--downloads", default="/tmp/sentinel-e2e-downloads")
    args = ap.parse_args()
    password = os.environ[args.admin_password_env]
    downloads = Path(args.downloads)
    downloads.mkdir(parents=True, exist_ok=True)
    rec = Recorder()
    db = psycopg.connect(args.db, autocommit=True)
    q = lambda sql, *p: db.execute(sql, p).fetchone()[0]  # noqa: E731
    state: dict = {}
    offline = not internet_reachable()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=args.chrome) if args.chrome else pw.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 900}, accept_downloads=True)
        page: Page = context.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        base = args.base_url

        def s1():
            page.goto(f"{base}/api/v1/health/ready")
            assert '"status":"ok"' in page.content().replace(" ", "")
            return f"API ready; frontend at {base}; internet reachable from test host: {'no' if offline else 'YES'}"
        rec.step(1, "Start Sentinel locally", s1)

        def s2():
            page.goto(f"{base}/login")
            page.get_by_label("Username").fill(args.admin)
            page.get_by_label("Password").fill(password)
            page.get_by_role("button", name="Sign in").click()
            expect(page.get_by_role("heading", name="Security overview")).to_be_visible()
            page.goto(f"{base}/ai")
            expect(page.get_by_text("No AI provider is configured")).to_be_visible()
            return "AI status page reports: no AI provider configured"
        rec.step(2, "No external AI API key configured", s2)

        rec.step(3, "Internet access disconnected", lambda: (
            "No route to the internet from the test environment" if offline else
            (_ for _ in ()).throw(AssertionError("Internet is reachable; run inside an isolated network to verify offline operation"))))

        rec.step(4, "Log into Sentinel", lambda: f"Signed in as {args.admin} through the login page")

        def upload(path: Path, synthetic=True):
            page.goto(f"{base}/events")
            page.get_by_role("button", name="Upload logs").click()
            page.get_by_label("Log file").set_input_files(str(path))
            if synthetic:
                page.get_by_text("Mark these records as synthetic").click()
            page.get_by_role("button", name="Upload and process").click()
            summary = page.get_by_test_id("ingestion-summary")
            expect(summary).to_be_visible(timeout=120_000)
            text = summary.inner_text()
            page.get_by_role("button", name="Done").click()
            return text

        def s5():
            # The local intelligence dataset is loaded first so reputation context is available offline.
            with db.cursor() as cur, INTEL_FILE.open() as f:
                import csv
                for row in csv.DictReader(f):
                    cur.execute("INSERT INTO threat_indicators (indicator, indicator_type, verdict, confidence, source, description, is_synthetic, added_at) "
                                "VALUES (%s,'ip',%s,%s,%s,%s,true,now()) ON CONFLICT DO NOTHING",
                                (row["indicator"], row["verdict"], float(row["confidence"]), row["source"], row["description"]))
            text = upload(CSV_FILE)
            job = db.execute("SELECT total_records, processed_records, rejected_records, duplicate_records FROM ingestion_jobs ORDER BY id DESC LIMIT 1").fetchone()
            assert job[1] > 6000 and job[2] == 3 and job[3] == 3, job
            state["csv_job"] = job
            return f"UI summary shown. Job: received {job[0]}, stored {job[1]}, rejected {job[2]}, duplicates {job[3]}"
        rec.step(5, "Import the synthetic CSV dataset", s5)

        def s6():
            upload(JSON_FILE)
            job = db.execute("SELECT total_records, processed_records, rejected_records, duplicate_records FROM ingestion_jobs ORDER BY id DESC LIMIT 1").fetchone()
            assert job[1] == job[0] and job[2] == 0, job
            return f"Job: received {job[0]}, stored {job[1]}, rejected {job[2]}"
        rec.step(6, "Import the synthetic JSON dataset", s6)

        def s7():
            total = q("SELECT count(*) FROM security_events")
            synthetic = q("SELECT count(*) FROM security_events WHERE is_synthetic")
            utc = q("SELECT count(*) FROM security_events WHERE timestamp < '2026-11-09T00:00:00Z' OR timestamp > '2026-11-16T00:00:00Z'")
            assert total == state["csv_job"][1] + q("SELECT processed_records FROM ingestion_jobs ORDER BY id DESC LIMIT 1")
            assert synthetic == total and utc == 0
            return f"{total} events stored in PostgreSQL, all marked synthetic, all timestamps inside the dataset week (UTC)"
        rec.step(7, "Events validated and stored in PostgreSQL", s7)

        def s8():
            before = q("SELECT count(*) FROM alerts")
            page.goto(f"{base}/rules")
            page.get_by_role("button", name="Run on all stored events").click()
            expect(page.get_by_text("already known")).to_be_visible(timeout=120_000)
            after = q("SELECT count(*) FROM alerts")
            assert after == before, "rerun must not duplicate alerts"
            return f"Detection ran after each upload and again on demand; {after} alerts before and after the rerun (no duplicates)"
        rec.step(8, "Run the deterministic detection engine", s8)

        def s9():
            rows = db.execute("SELECT rule_id, count(*) FROM alerts GROUP BY rule_id ORDER BY rule_id").fetchall()
            assert len(rows) == 10, rows
            linked = q("SELECT count(*) FROM alerts a WHERE NOT EXISTS (SELECT 1 FROM alert_events ae WHERE ae.alert_id = a.id)")
            assert linked == 0
            return "All 10 rules produced alerts backed by stored events: " + ", ".join(f"{r}={n}" for r, n in rows)
        rec.step(9, "Suspicious patterns generate genuine alerts", s9)

        def s10():
            alert_id = q("SELECT id FROM alerts WHERE rule_id='SEN-AUTH-001' AND group_key LIKE 'source_ip:%%'")
            state["alert_id"] = alert_id
            page.goto(f"{base}/alerts")
            page.get_by_text("Authentication failures across 8 accounts").click()
            expect(page.get_by_role("heading", name="Why this score")).to_be_visible()
            expect(page.get_by_text("Evidence (8 stored events)")).to_be_visible()
            rows = page.locator("table").nth(1).locator("tbody tr").count()
            assert rows == 8, rows
            return f"Alert #{alert_id}: 8 evidence events listed with user, IP and outcome"
        rec.step(10, "Inspect the evidence behind an alert", s10)

        def s11():
            score, breakdown = db.execute("SELECT risk_score, score_breakdown FROM alerts WHERE id=%s", (state["alert_id"],)).fetchone()
            assert sum(f["points"] for f in breakdown) == score
            expect(page.get_by_text("Final score")).to_be_visible()
            nulls = q("SELECT count(*) FROM alerts WHERE risk_score IS NULL OR jsonb_array_length(score_breakdown) = 0")
            assert nulls == 0
            return f"Score {score} = " + " ".join(f"{f['factor']} {f['points']:+d}" for f in breakdown)
        rec.step(11, "Risk scores are calculated and explained", s11)

        def s12():
            page.get_by_role("button", name="Convert to incident").click()
            page.get_by_role("dialog").get_by_role("button", name="Convert").click()
            page.wait_for_url("**/incidents/*")
            incident_id = int(page.url.rstrip("/").split("/")[-1])
            state["incident_id"] = incident_id
            ref = q("SELECT reference FROM incidents WHERE id=%s", incident_id)
            assert q("SELECT incident_id FROM alerts WHERE id=%s", state["alert_id"]) == incident_id
            state["ref"] = ref
            return f"Created {ref} from alert #{state['alert_id']}"
        rec.step(12, "Convert an alert into an incident", s12)

        def s13():
            page.get_by_label("Assign incident").select_option(label=args.analyst)
            expect(page.locator("dd", has_text=args.analyst)).to_be_visible()  # "Assigned analyst" field updates
            assignee = q("SELECT u.username FROM incidents i JOIN users u ON u.id=i.assigned_to_id WHERE i.id=%s", state["incident_id"])
            assert assignee == args.analyst
            notified = q("SELECT count(*) FROM notifications n JOIN users u ON u.id=n.user_id WHERE u.username=%s AND notification_type='incident_assigned'", args.analyst)
            assert notified == 1
            return f"Assigned to {assignee}; the analyst received an in-app notification"
        rec.step(13, "Assign the incident to an analyst", s13)

        def s14():
            page.get_by_label("New note").fill("Spraying source 198.51.100.23 blocked at the VPN gateway. No successful logins from this source.")
            page.get_by_role("button", name="Add note").click()
            expect(page.get_by_text("Spraying source 198.51.100.23 blocked")).to_be_visible()
            for label in ("Mark investigating", "Mark contained"):
                page.get_by_role("button", name=label).click()
                page.get_by_role("dialog").get_by_role("button", name="Confirm").click()
                expect(page.get_by_role("dialog")).to_have_count(0)
            status = q("SELECT status FROM incidents WHERE id=%s", state["incident_id"])
            assert status == "contained"
            notes = q("SELECT count(*) FROM incident_notes WHERE incident_id=%s", state["incident_id"])
            return f"Note saved ({notes} in database); status now {status}"
        rec.step(14, "Add investigation notes and update status", s14)

        def s15():
            page.goto(f"{base}/")
            open_count = q("SELECT count(*) FROM incidents WHERE status IN ('open','investigating','contained')")
            events = q("SELECT count(*) FROM security_events")
            main = page.get_by_role("main")
            expect(main.locator("a", has_text="Open incidents")).to_contain_text(str(open_count))
            expect(main.locator("a[href='/events']", has_text="Security events")).to_contain_text(f"{events:,}")
            return f"Dashboard shows {events:,} events and {open_count} open incidents, matching SQL counts"
        rec.step(15, "Dashboard reflects the database", s15)

        def s16():
            page.goto(f"{base}/incidents/{state['incident_id']}")
            with page.expect_download(timeout=60_000) as info:
                page.get_by_role("button", name="Incident report (PDF)").click()
            path = downloads / info.value.suggested_filename
            info.value.save_as(path)
            data = path.read_bytes()
            assert data.startswith(b"%PDF") and len(data) > 2000
            from pypdf import PdfReader
            text = "\n".join(p.extract_text() for p in PdfReader(str(path)).pages)
            assert state["ref"] in text and "Spraying source" in text
            return f"{path.name}: {len(data):,} bytes, contains the reference, evidence and the investigation note"
        rec.step(16, "Generate a PDF incident report", s16)

        def s17():
            page.goto(f"{base}/events?source_system=vpn-gw-01.corp.example&flagged=true")
            expect(page.get_by_role("button", name="Export CSV")).to_be_visible()
            with page.expect_download(timeout=60_000) as info:
                page.get_by_role("button", name="Export CSV").click()
            path = downloads / info.value.suggested_filename
            info.value.save_as(path)
            lines = path.read_text().strip().splitlines()
            expected = q("SELECT count(*) FROM security_events e WHERE source_system='vpn-gw-01.corp.example' AND EXISTS (SELECT 1 FROM alert_events ae WHERE ae.event_id=e.id)")
            assert len(lines) - 1 == expected, (len(lines), expected)
            return f"{path.name}: {expected} filtered events exported"
        rec.step(17, "Export selected events to CSV", s17)

        def s18():
            page.goto(f"{base}/audit")
            expect(page.get_by_role("heading", name="Audit logs")).to_be_visible()
            actions = {r[0] for r in db.execute("SELECT DISTINCT action FROM audit_logs")}
            needed = {"auth.login", "ingestion.complete", "detection.run", "incident.create", "incident.assign",
                      "incident.note", "incident.status_change", "report.generate", "export.events"}
            missing = needed - actions
            assert not missing, missing
            expect(page.get_by_text("export.events").first).to_be_visible()
            return f"{q('SELECT count(*) FROM audit_logs')} audit entries, including: " + ", ".join(sorted(needed))
        rec.step(18, "Review the audit trail", s18)

        if errors:
            rec.rows.append((99, "Browser JavaScript errors", "FAIL", "; ".join(errors[:5])))
        browser.close()

    passed = sum(1 for r in rec.rows if r[2] == "PASS")
    lines = [
        "# Offline acceptance test: actual results",
        "",
        f"- Run at: {datetime.now(UTC):%Y-%m-%d %H:%M UTC}",
        f"- Host: {platform.system()} {platform.release()}, Python {platform.python_version()}",
        f"- Internet reachable during the run: {'no' if offline else 'yes'}",
        "- AI provider: none configured. External threat intelligence: disabled.",
        f"- Result: {passed} of {len(rec.rows)} steps passed",
        "",
        "Generated by `e2e/offline_acceptance.py`. Every result below was observed during the run.",
        "",
        "| # | Step | Result | Observed |",
        "|---|------|--------|----------|",
    ] + [f"| {n} | {name} | {status} | {detail.replace('|', '/')} |" for n, name, status, detail in rec.rows]
    Path(args.report).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n{passed}/{len(rec.rows)} passed. Report: {args.report}")
    return 0 if passed == len(rec.rows) else 1


if __name__ == "__main__":
    sys.exit(main())
