#!/usr/bin/env python3
from playwright.sync_api import sync_playwright
import sys

URL = "http://localhost:8000"

def main():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        resp = page.goto(URL, timeout=20000)
        status = resp.status if resp else None
        if not resp or status != 200:
            print(f"PLAYWRIGHT_FAIL: status={status}")
            return 2

        # Count terminal panes
        terminal_count = page.locator('.terminal-flicker').count()
        session_panels = page.locator('.neon-panel').count()
        title = page.title()
        print(f"PLAYWRIGHT_OK: status=200 title={title} terminals={terminal_count} neon_panels={session_panels}")
        browser.close()
        return 0

if __name__ == '__main__':
    sys.exit(main())
