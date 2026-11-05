"""Real-browser check of the running console: signs in, visits every page at desktop and phone
width, saves screenshots, and fails on console errors or failed requests.

    python scripts/browser_check.py [--base http://127.0.0.1:8501] [--out .impeccable/review]

Needs Playwright (pip install playwright) and an installed Chrome. Credentials are read from
secrets/LOCAL-CREDENTIALS.txt, which scripts/make_secrets.py users create for local testing.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
PAGES = ["/", "/events", "/alerts", "ALERT", "/sources", "SOURCE", "EVENT", "/sensors", "/mitre", "/owasp", "/settings"]


def settle(page) -> None:
    """The live-update stream keeps a request open, so wait for skeletons to go instead of network idle."""
    page.wait_for_timeout(400)
    page.wait_for_function("!document.querySelector('.skeleton')", timeout=15000)
    page.wait_for_timeout(600)


def credentials() -> tuple[str, str]:
    text = (ROOT / "secrets" / "LOCAL-CREDENTIALS.txt").read_text(encoding="utf-8")
    user = re.search(r"username:\s*(\S+)", text).group(1)
    password = re.search(r"password:\s*(\S+)", text).group(1)
    return user, password


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8501")
    ap.add_argument("--out", default=str(ROOT / ".impeccable" / "review"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    user, password = credentials()
    problems: list[str] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="chrome", headless=True)
        for label, size in (("desktop", {"width": 1440, "height": 900}), ("mobile", {"width": 390, "height": 844})):
            ctx = browser.new_context(viewport=size)
            page = ctx.new_page()
            page.on("console", lambda m, l=label: m.type == "error" and problems.append(f"{l} console: {m.text}"))
            page.on("requestfailed", lambda r, l=label: problems.append(f"{l} request failed: {r.url}")
                    if "/api/stream" not in r.url else None)
            page.goto(args.base)
            page.fill("input[autocomplete=username]", user)
            page.fill("input[type=password]", password)
            page.click("button:has-text('Sign in')")
            page.wait_for_selector("h1:has-text('Overview')", timeout=15000)
            for path in PAGES:
                if path == "ALERT":
                    page.goto(args.base + "/alerts")
                    settle(page)
                    link = page.locator("table.data tbody a[href^='/alerts/']").first
                    if not link.count():
                        continue
                    path = link.get_attribute("href")
                elif path == "SOURCE":
                    page.goto(args.base + "/sources")
                    settle(page)
                    link = page.locator("table.data tbody a[href^='/sources/']").first
                    if not link.count():
                        continue
                    path = link.get_attribute("href")
                elif path == "EVENT":
                    page.goto(args.base + "/events?detection=alerted")
                    settle(page)
                    page.locator("table.data tbody tr").first.click()
                    page.wait_for_url(re.compile(r".*/events/[^?]+$"))
                    path = page.url.replace(args.base, "")
                page.goto(args.base + path)
                settle(page)
                name = {"/": "overview"}.get(path, path.strip("/").split("/")[0] + ("-detail" if path.count("/") > 1 else ""))
                page.screenshot(path=str(out / f"{label}-{name}.png"), full_page=True)
                if page.locator("h3:has-text('Could not load this'), h3:has-text('Data unavailable')").count():
                    problems.append(f"{label} {path}: error state shown")
                overflow = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
                if overflow > 1:
                    problems.append(f"{label} {path}: horizontal page overflow {overflow}px")
            ctx.close()
        browser.close()
    for p in problems:
        print("PROBLEM", p)
    print(f"screenshots in {out}; {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
