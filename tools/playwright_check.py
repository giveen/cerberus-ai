#!/usr/bin/env python3
from playwright.sync_api import sync_playwright
import sys, time

URL = "http://localhost:8000"
MAX_ATTEMPTS = 30
DELAY = 2

def main():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                resp = page.goto(URL, timeout=10000)
                status = resp.status if resp else None
                if resp and status == 200:
                    title = page.title() or ""
                    print(f"PLAYWRIGHT_OK: status=200 title={title}")
                    browser.close()
                    return 0
                else:
                    print(f"Attempt {attempt}/{MAX_ATTEMPTS}: status={status}")
            except Exception as e:
                print(f"Attempt {attempt}/{MAX_ATTEMPTS}: exception={e}")
            time.sleep(DELAY)
        browser.close()
        print("PLAYWRIGHT_FAIL: dashboard not reachable")
        return 2

if __name__ == "__main__":
    sys.exit(main())
