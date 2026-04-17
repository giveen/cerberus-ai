"""
Playwright test to walk through the dashboard and test nmap scan prompt.
"""
import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    from playwright.async_api import async_playwright, expect
except ImportError:
    print("Playwright not installed. Installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "playwright"])
    from playwright.async_api import async_playwright, expect


async def test_dashboard_nmap_scan():
    """Test the dashboard with nmap scan prompt."""
    async with async_playwright() as p:
        # Launch browser
        print("Launching browser...")
        browser = await p.chromium.launch(headless=False)
        page = await browser.new_page()
        
        # Navigate to dashboard
        print("Navigating to dashboard at http://localhost:8000...")
        try:
            await page.goto("http://localhost:8000", wait_until="networkidle", timeout=30000)
        except Exception as e:
            print(f"Error navigating to dashboard: {e}")
            await browser.close()
            return
        
        print("Dashboard loaded. Taking screenshot...")
        await page.screenshot(path="/tmp/dashboard_initial.png")
        
        # Look for input field
        print("Looking for input/prompt field...")
        
        # Wait a moment for page to fully load
        await page.wait_for_timeout(2000)
        
        # Try to find text input or textarea
        inputs = await page.query_selector_all("input[type='text'], textarea, [contenteditable='true']")
        print(f"Found {len(inputs)} potential input fields")
        
        if inputs:
            # Click on the first input field
            print("Clicking on first input field...")
            await inputs[0].click()
            await page.wait_for_timeout(500)
            
            # Type the prompt
            prompt = "Perform a nmap scan of 192.168.0.4, and only look for the Top 1000 ports. Then summarize your findings and provide recommendations for next phase"
            print(f"Entering prompt: {prompt}")
            await inputs[0].fill(prompt)
            await page.wait_for_timeout(500)
            
            # Take screenshot of prompt entry
            await page.screenshot(path="/tmp/dashboard_prompt_entered.png")
            
            # Look for submit button
            print("Looking for submit button...")
            buttons = await page.query_selector_all("button")
            print(f"Found {len(buttons)} buttons")
            
            # Print button text for debugging
            for i, btn in enumerate(buttons):
                text = await btn.text_content()
                print(f"  Button {i}: {text}")
            
            # Try to find and click submit/send button
            submit_button = None
            for btn in buttons:
                text = await btn.text_content()
                if text and any(word in text.lower() for word in ["send", "submit", "run", "execute"]):
                    submit_button = btn
                    break
            
            if submit_button:
                print("Found submit button, clicking...")
                await submit_button.click()
                await page.wait_for_timeout(2000)
            else:
                # Try pressing Enter
                print("No submit button found, trying to press Enter...")
                await inputs[0].press("Enter")
                await page.wait_for_timeout(2000)
            
            # Wait for response
            print("Waiting for response...")
            await page.wait_for_timeout(5000)
            
            # Take screenshot of response
            await page.screenshot(path="/tmp/dashboard_response.png")
            
            # Get page content
            content = await page.content()
            print("\n=== Page HTML (first 2000 chars) ===")
            print(content[:2000])
            print("...")
            
            # Look for response content
            body = await page.query_selector("body")
            if body:
                text = await body.text_content()
                print("\n=== Page text content (last 2000 chars) ===")
                print(text[-2000:] if len(text) > 2000 else text)
        else:
            print("No input fields found on page")
            content = await page.content()
            print("\n=== Page HTML ===")
            print(content[:1000])
        
        # Check browser console for errors
        print("\n=== Checking browser logs ===")
        
        # Try to capture console messages
        page.on("console", lambda msg: print(f"[{msg.type}] {msg.text}"))
        
        # Keep browser open for a bit
        await page.wait_for_timeout(3000)
        
        await browser.close()
        print("\nTest completed.")


if __name__ == "__main__":
    asyncio.run(test_dashboard_nmap_scan())
