import { expect, test, type Locator, type Page } from '@playwright/test';

async function openDrawerAndHealth(page: Page, drawerTrigger: Locator) {
  await drawerTrigger.click();
  await page.getByText('System Health').click();
}

async function closeDrawer(page: Page) {
  await page.keyboard.press('Escape');
}

test.describe('Nmap execution pipeline', () => {
  test.setTimeout(120_000);

  test('executes nmap prompt and streams tool output to completion', async ({ page }) => {
    await page.goto('/');

    const terminalInput = page.getByPlaceholder(
      'Type a prompt for the active agent. Press Enter to send.'
    );
    const drawerTrigger = page.locator('[data-drawer-trigger="metadata"]');
    const busyNodesValue = page.locator('[data-stat-value="busy-nodes"]:visible');

    await expect(terminalInput).toBeEnabled();
    await openDrawerAndHealth(page, drawerTrigger);
    await expect(busyNodesValue.first()).toHaveText('0');
    await closeDrawer(page);

    await terminalInput.fill('Perform a fast nmap scan on 127.0.0.1');
    await terminalInput.press('Enter');

    // Busy transition should happen immediately after dispatch.
    await expect(terminalInput).toBeDisabled();
    await openDrawerAndHealth(page, drawerTrigger);
    await expect(busyNodesValue.first()).toHaveText('1', { timeout: 30_000 });
    await closeDrawer(page);

    // Wait for evidence of tool execution/results in terminal output.
    const toolSignal = page.getByText(/PORT|STATE|SERVICE|Nmap done|Starting Nmap/i).first();
    await expect(toolSignal).toBeVisible({ timeout: 120_000 });

    // Terminal should eventually return to ACTIVE/idle state.
    await openDrawerAndHealth(page, drawerTrigger);
    await expect(busyNodesValue.first()).toHaveText('0', { timeout: 120_000 });
    await closeDrawer(page);
  });
});
