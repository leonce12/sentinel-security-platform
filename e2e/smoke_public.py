"""Browser smoke test for a deployed Sentinel (local or public).

Checks the landing page, the read-only demo, every page a Viewer can open, that administrative
pages are refused, console errors (including CSP violations), the mobile layout and, if a
password is supplied, an administrator sign-in. Writes the observed result of each check.

    python e2e/smoke_public.py --base-url https://sentinel-security-platform.onrender.com \
        --report docs/live-smoke-results.md [--admin sonia.admin --admin-password-env SENTINEL_ADMIN_PASSWORD]
"""

import argparse
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

VIEWER_PAGES = [("/", "Security overview"), ("/events", "Security events"), ("/alerts", "Alerts"),
                ("/incidents", "Incidents"), ("/rules", "Detection rules"), ("/reports", "Reports"),
                ("/notifications", "Notifications"), ("/profile", "Demo account")]
ADMIN_ONLY = ["/audit", "/users", "/settings"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--report", default=None)
    ap.add_argument("--screenshots", default=None, help="folder for screenshots")
    ap.add_argument("--admin", default=None)
    ap.add_argument("--admin-password-env", default="SENTINEL_ADMIN_PASSWORD")
    ap.add_argument("--chrome", default=os.environ.get("CHROME_PATH"))
    args = ap.parse_args()
    base = args.base_url.rstrip("/")
    shots = Path(args.screenshots) if args.screenshots else None
    if shots:
        shots.mkdir(parents=True, exist_ok=True)
    rows: list[tuple[str, str, str]] = []
    console: list[str] = []

    def check(name, fn):
        start = time.perf_counter()
        try:
            detail = fn() or ""
            rows.append((name, "PASS", f"{detail} ({time.perf_counter() - start:.1f}s)"))
            print(f"[PASS] {name}: {detail}")
        except Exception as exc:
            rows.append((name, "FAIL", f"{type(exc).__name__}: {str(exc).splitlines()[0][:250]}"))
            print(f"[FAIL] {name}: {exc}")

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=args.chrome) if args.chrome else p.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()
        page.on("console", lambda m: m.type == "error" and console.append(m.text))
        page.on("pageerror", lambda e: console.append(f"pageerror: {e}"))

        def landing():
            response = page.goto(base + "/", timeout=120_000)  # free hosts may need a minute to wake up
            assert response and response.ok, response and response.status
            expect(page.get_by_role("heading", name="Find the events that matter, and explain why they matter.")).to_be_visible(timeout=60_000)
            if shots:
                page.screenshot(path=str(shots / "live-landing.png"))
            return f"HTTP {response.status}, {'HTTPS' if page.url.startswith('https://') else 'HTTP'}"
        check("Landing page loads", landing)

        def health():
            r = page.request.get(base + "/api/v1/health/ready")
            assert r.ok, r.status
            body = r.json()
            assert body["status"] == "ok"
            return f"{body}"
        check("Backend health and database", health)

        def headers():
            h = page.request.get(base + "/").headers
            missing = [k for k in ("content-security-policy", "x-frame-options", "x-content-type-options") if k not in h]
            assert not missing, missing
            docs = page.request.get(base + "/api/v1/docs").status
            return f"CSP, X-Frame-Options, nosniff present; HSTS {'present' if 'strict-transport-security' in h else 'absent'}; API docs HTTP {docs}"
        check("Security headers", headers)

        def demo():
            page.goto(base + "/")
            page.get_by_role("button", name="Explore the live demo").click()
            expect(page.get_by_role("heading", name="Security overview")).to_be_visible(timeout=60_000)
            expect(page.get_by_text("Demo (read-only)")).to_be_visible()
            page.wait_for_load_state("networkidle")
            events = page.locator("main a[href='/events']").first.inner_text()
            if shots:
                page.screenshot(path=str(shots / "live-dashboard.png"))
            return f"Signed in as read-only viewer; events tile shows: {' '.join(events.split())}"
        check("Read-only demo sign-in", demo)

        def viewer_pages():
            for path, heading in VIEWER_PAGES:
                page.goto(base + path)
                expect(page.get_by_role("heading", name=heading, exact=True)).to_be_visible(timeout=30_000)
                page.wait_for_load_state("networkidle")
            return f"{len(VIEWER_PAGES)} pages opened"
        check("Viewer pages load", viewer_pages)

        def details():
            page.goto(base + "/alerts?sort=risk_score&order=desc")
            page.locator("tbody tr").first.click()
            expect(page.get_by_role("heading", name="Why this score")).to_be_visible(timeout=30_000)
            assert page.get_by_role("button", name="Convert to incident").count() == 0
            page.goto(base + "/incidents")
            page.locator("tbody tr").first.click()
            expect(page.get_by_role("heading", name="Timeline")).to_be_visible(timeout=30_000)
            return "Alert and incident details open; no change controls shown to the viewer"
        check("Alert and incident details", details)

        def refused():
            for path in ADMIN_ONLY:
                page.goto(base + path)
                expect(page.get_by_text("Access denied")).to_be_visible()
            api = page.request.get(base + "/api/v1/audit-logs")
            return f"{', '.join(ADMIN_ONLY)} refused in the UI; unauthenticated API request gets HTTP {api.status}"
        check("Administrative pages refused", refused)

        def mobile():
            page.set_viewport_size({"width": 390, "height": 844})
            page.goto(base + "/")
            expect(page.get_by_role("heading", name="Security overview")).to_be_visible(timeout=30_000)
            page.get_by_role("button", name="Open menu").click()
            expect(page.get_by_role("navigation", name="Main")).to_be_visible()
            overflow = page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 1")
            if shots:
                page.screenshot(path=str(shots / "live-mobile.png"))
            page.set_viewport_size({"width": 1440, "height": 900})
            assert not overflow, "page wider than the phone screen"
            return "Dashboard and menu usable at 390 px, no horizontal overflow"
        check("Mobile layout", mobile)

        def sign_out():
            page.get_by_role("button", name="Sign out").click()
            expect(page.get_by_role("heading", name="Find the events that matter, and explain why they matter.")).to_be_visible()
            return "Back on the landing page"
        check("Sign out", sign_out)

        password = os.environ.get(args.admin_password_env)
        if args.admin and password:
            def admin():
                page.goto(base + "/login")
                page.get_by_label("Username").fill(args.admin)
                page.get_by_label("Password").fill(password)
                page.get_by_role("button", name="Sign in").click()
                expect(page.get_by_role("heading", name="Security overview")).to_be_visible(timeout=30_000)
                for path, heading in (("/audit", "Audit logs"), ("/users", "User management"), ("/settings", "Settings")):
                    page.goto(base + path)
                    expect(page.get_by_role("heading", name=heading, exact=True)).to_be_visible()
                page.get_by_role("button", name="Sign out").click()
                return "Administrator signed in and opened audit logs, users and settings"
            check("Administrator sign-in", admin)

        real_errors = [c for c in console if "401" not in c]
        rows.append(("Console errors", "PASS" if not real_errors else "FAIL",
                     "none" if not real_errors else "; ".join(real_errors[:5])))
        print(f"[{'PASS' if not real_errors else 'FAIL'}] Console errors: {real_errors or 'none'}")
        browser.close()

    passed = sum(r[1] == "PASS" for r in rows)
    if args.report:
        lines = [f"# Live site smoke test: {base}", "", f"- Run at: {datetime.now(UTC):%Y-%m-%d %H:%M UTC}",
                 f"- Result: {passed} of {len(rows)} checks passed", "",
                 "| Check | Result | Observed |", "|---|---|---|"]
        lines += [f"| {n} | {s} | {d.replace('|', '/')} |" for n, s, d in rows]
        Path(args.report).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{passed}/{len(rows)} passed")
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
