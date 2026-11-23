"""Capture screenshots of the running application for the README.

The screenshots show the real application with the synthetic demo dataset loaded. Usage:

    python scripts/capture_screenshots.py --base-url http://localhost:5173 \
        --username admin --password-env SENTINEL_SCREENSHOT_PASSWORD

Requires: pip install playwright, and a Chromium/Chrome browser (python -m playwright install chromium).
"""

import argparse
import os
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

PAGES = [
    ("dashboard", "/", "Security overview"),
    ("events", "/events", "Security events"),
    ("alerts", "/alerts", "Alerts"),
    ("incidents", "/incidents", "Incidents"),
    ("intel", "/intel?ip=203.0.113.45", "Threat intelligence"),
    ("rules", "/rules", "Detection rules"),
    ("ai-analyst", "/ai", "AI security analyst"),
    ("reports", "/reports", "Reports"),
    ("notifications", "/notifications", "Notifications"),
    ("audit", "/audit", "Audit logs"),
    ("users", "/users", "User management"),
    ("settings", "/settings", "Settings"),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:5173")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password-env", default="SENTINEL_SCREENSHOT_PASSWORD")
    parser.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "docs" / "screenshots"))
    parser.add_argument("--chrome", default=os.environ.get("CHROME_PATH"))
    args = parser.parse_args()
    password = os.environ.get(args.password_env)
    if not password:
        print(f"Set {args.password_env}", file=sys.stderr)
        return 1
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=args.chrome) if args.chrome else p.chromium.launch()
        page = browser.new_page(viewport={"width": 1500, "height": 950}, device_scale_factor=1)
        # The first /auth/refresh before sign-in returns 401 by design (no session yet); ignore only that.
        page.on("console", lambda m: m.type == "error" and "401" not in m.text and problems.append(f"console: {m.text}"))
        page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))

        page.goto(f"{args.base_url}/login")
        page.screenshot(path=str(out / "login.png"))
        page.get_by_label("Username").fill(args.username)
        page.get_by_label("Password").fill(password)
        page.get_by_role("button", name="Sign in").click()
        page.get_by_role("heading", name="Security overview").wait_for()

        for name, path, heading in PAGES:
            page.goto(f"{args.base_url}{path}")
            page.get_by_role("heading", name=heading, exact=True).wait_for()
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(600)
            page.screenshot(path=str(out / f"{name}.png"), full_page=name in ("dashboard",))

        # Detail pages: highest-risk alert and the first incident
        page.goto(f"{args.base_url}/alerts?sort=risk_score&order=desc")
        page.locator("tbody tr").first.click()
        page.wait_for_load_state("networkidle")
        page.screenshot(path=str(out / "alert-detail.png"), full_page=True)
        page.goto(f"{args.base_url}/incidents")
        page.locator("tbody tr").first.click()
        page.wait_for_load_state("networkidle")
        page.screenshot(path=str(out / "incident-detail.png"), full_page=True)

        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(f"{args.base_url}/")
        page.get_by_role("heading", name="Security overview").wait_for()
        page.wait_for_load_state("networkidle")
        page.screenshot(path=str(out / "mobile-dashboard.png"))
        browser.close()

    for item in problems:
        print(item)
    print(f"Saved screenshots to {out}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
