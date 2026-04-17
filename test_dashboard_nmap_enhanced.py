"""
Enhanced Playwright test to walk through the dashboard and test nmap scan prompt.
"""
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    from playwright.async_api import async_playwright, expect
except ImportError:
    print("Playwright not installed. Installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "playwright"])
    from playwright.async_api import async_playwright, expect


async def test_dashboard_nmap_scan_enhanced():
    """Enhanced test with longer wait times and detailed error checking."""
    async with async_playwright() as p:
        print("Launching browser...")
        browser = await p.chromium.launch(headless=False)
        page = await browser.new_page()
        
        # Set viewport for consistent screenshots
        await page.set_viewport_size({"width": 1280, "height": 720})
        
        print("Navigating to dashboard at http://localhost:8000...")
        try:
            await page.goto("http://localhost:8000", wait_until="networkidle", timeout=30000)
        except Exception as e:
            print(f"Error navigating to dashboard: {e}")
            await browser.close()
            return
        
        print("Dashboard loaded. Taking screenshot...")
        await page.screenshot(path="/tmp/dashboard_enhanced_initial.png")
        
        # Wait for page to fully load
        await page.wait_for_timeout(3000)
        
        # Find input field
        print("Looking for input/prompt field...")
        inputs = await page.query_selector_all("input[type='text'], textarea, [contenteditable='true']")
        print(f"Found {len(inputs)} potential input fields")
        
        if inputs:
            # Click on the first input field
            print("Clicking on first input field...")
            await inputs[0].click()
            await page.wait_for_timeout(500)
            
            # Type the prompt
            prompt = "Perform a nmap scan of 192.168.0.4, and only look for the Top 1000 ports. Then summarize your findings and provide recommendations for next phase"
            print(f"Entering prompt...")
            await inputs[0].fill(prompt)
            await page.wait_for_timeout(500)
            
            # Take screenshot of prompt entry
            await page.screenshot(path="/tmp/dashboard_enhanced_prompt_entered.png")
            
            # Look for and click submit/run button
            print("Looking for Run button...")
            buttons = await page.query_selector_all("button")
            submit_button = None
            for btn in buttons:
                text = await btn.text_content()
                if text and "Run" in text:
                    submit_button = btn
                    break
            
            if submit_button:
                print("Clicking Run button...")
                await submit_button.click()
                await page.wait_for_timeout(2000)
            
            # Wait for execution to complete or show results
            print("Waiting for execution (30 seconds)...")
            for i in range(6):
                await page.wait_for_timeout(5000)
                
                # Take periodic screenshots
                await page.screenshot(path=f"/tmp/dashboard_enhanced_execution_{i}.png")
                
                # Get page text to check for results
                body = await page.query_selector("body")
                if body:
                    text = await body.text_content()
                    
                    # Check for indicators of execution
                    if "nmap" in text.lower():
                        print(f"  [{i*5}s] Found 'nmap' in page content")
                    if "finding" in text.lower() or "recommendation" in text.lower():
                        print(f"  [{i*5}s] Found results or recommendations")
                    if "clear error" in text.lower():
                        print(f"  [{i*5}s] Found error indicator")
                    if "port" in text.lower() and ("open" in text.lower() or "closed" in text.lower()):
                        print(f"  [{i*5}s] Found port scan results")
            
            # Take final screenshot
            print("Taking final screenshot...")
            await page.screenshot(path="/tmp/dashboard_enhanced_final.png")
            
            # Get detailed page content
            body = await page.query_selector("body")
            if body:
                text = await body.text_content()
                print("\n=== Page text content (last 3000 chars) ===")
                print(text[-3000:] if len(text) > 3000 else text)
            
            # Look for error message  
            error_buttons = await page.query_selector_all("button")
            for btn in error_buttons:
                text = await btn.text_content()
                if text and "error" in text.lower():
                    print(f"\n=== Found error button: {text} ===")
                    
                    # Try to click it to reveal the error
                    parent = await btn.evaluate("el => el.parentElement")
                    if parent:
                        error_text = await parent.evaluate("el => el.textContent")
                        print(f"Error context: {error_text[:500]}")
        else:
            print("No input fields found on page")
        
        await browser.close()
        print("\nEnhanced test completed.")


if __name__ == "__main__":
    asyncio.run(test_dashboard_nmap_scan_enhanced())
