import { expect, test } from '@playwright/test';

test.describe('Nmap execution pipeline', () => {
  test.setTimeout(120_000);

  test('executes nmap prompt and streams tool output to completion', async ({ page }) => {
    await page.goto('/');

    const terminalInput = page.getByPlaceholder(
      'Type a prompt for the active agent. Press Enter to send.'
    );
    const busyNodesLabel = page.getByText('BUSY NODES');
    const busyNodesValue = busyNodesLabel.locator('xpath=following-sibling::*[1]');

    await expect(terminalInput).toBeEnabled();
    await expect(busyNodesValue).toHaveText('0');

    await terminalInput.fill('Perform a fast nmap scan on 127.0.0.1');
    await terminalInput.press('Enter');

    // Busy transition should happen immediately after dispatch.
    await expect(terminalInput).toBeDisabled();
    await expect(busyNodesValue).toHaveText('1', { timeout: 30_000 });

    // Wait for evidence of tool execution/results in terminal output.
    const toolSignal = page.getByText(/PORT|STATE|SERVICE|Nmap done|Starting Nmap/i).first();
    await expect(toolSignal).toBeVisible({ timeout: 120_000 });

    // Terminal should eventually return to ACTIVE/idle state.
    await expect(busyNodesValue).toHaveText('0', { timeout: 120_000 });
    await expect(terminalInput).toBeEnabled({ timeout: 120_000 });
  });
});
