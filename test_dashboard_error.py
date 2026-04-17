"""
Playwright test to capture the error message from the dashboard.
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from playwright.async_api import async_playwright


async def test_dashboard_error():
    """Capture the error message displayed on dashboard."""
    async with async_playwright() as p:
        print("Launching browser...")
        browser = await p.chromium.launch(headless=False)
        page = await browser.new_page()
        
        await page.set_viewport_size({"width": 1280, "height": 720})
        
        print("Navigating to dashboard...")
        await page.goto("http://localhost:8000", wait_until="networkidle", timeout=30000)
        await page.wait_for_timeout(2000)
        
        # Find and interact with input
        inputs = await page.query_selector_all("input[type='text'], textarea")
        if inputs:
            print("Entering prompt...")
            await inputs[0].click()
            await inputs[0].fill("Perform a nmap scan of 192.168.0.4, and only look for the Top 1000 ports. Then summarize your findings and provide recommendations for next phase")
            await page.wait_for_timeout(500)
            
            # Click Run button
            buttons = await page.query_selector_all("button")
            for btn in buttons:
                text = await btn.text_content()
                if text and "Run" in text:
                    print("Clicking Run...")
                    await btn.click()
                    break
            
            # Wait and take screenshot
            await page.wait_for_timeout(5000)
            
            # Look for Clear Error button
            buttons = await page.query_selector_all("button")
            error_button = None
            for btn in buttons:
                text = await btn.text_content()
                if text and "Clear Error" in text:
                    error_button = btn
                    print("Found Clear Error button")
                    break
            
            if error_button:
                # Get the error element parent or sibling
                parent = await error_button.evaluate("el => el.parentElement")
                if parent:
                    # Try to find error text nearby
                    error_html = await page.content()
                    
                    # Look for error content in different ways
                    # Check if there's a toast or modal with error
                    error_divs = await page.query_selector_all("[role='alert'], [class*='error'], [class*='Error']")
                    print(f"\nFound {len(error_divs)} potential error elements")
                    
                    for div in error_divs:
                        text = await div.text_content()
                        if text and len(text.strip()) > 0:
                            print(f"Error element text: {text[:500]}")
            
            # Get page text
            body = await page.query_selector("body")
            if body:
                text = await body.text_content()
                # Find lines with "error", "Error", "failed", "Failed"
                lines = text.split('\n')
                for i, line in enumerate(lines):
                    if any(word in line.lower() for word in ['error', 'failed', 'exception']):
                        print(f"Line {i}: {line}")
            
            # Take screenshot showing the error button
            await page.screenshot(path="/tmp/dashboard_error_state.png")
            print("\nScreenshot saved to /tmp/dashboard_error_state.png")
        
        await browser.close()


if __name__ == "__main__":
    asyncio.run(test_dashboard_error())
