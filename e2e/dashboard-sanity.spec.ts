import { expect, test, type Locator, type Page } from '@playwright/test';

async function openDrawerAndHealth(page: Page, drawerTrigger: Locator) {
  await drawerTrigger.click();
  await page.getByText('System Health').click();
}

async function closeDrawer(page: Page) {
  await page.keyboard.press('Escape');
}

test.describe('Dashboard sanity', () => {
  test('renders core layout regions', async ({ page }) => {
    await page.goto('/');

    const drawerTrigger = page.locator('[data-drawer-trigger="metadata"]');
    const terminalInput = page.getByPlaceholder(
      'Type a prompt for the active agent. Press Enter to send.'
    );
    const executeButton = page.getByRole('button', { name: 'EXECUTE' });
    const stopButton = page.getByRole('button', { name: 'Stop' });
    const terminalPanel = page.getByText('Standing by for a prompt or command.');

    await expect(drawerTrigger).toBeVisible();
    await expect(terminalInput).toBeVisible();
    await expect(executeButton).toBeVisible();
    await expect(stopButton).toBeVisible();
    await expect(terminalPanel).toBeVisible();

    // Metadata now lives in a drawer; open it before asserting stat values.
  await openDrawerAndHealth(page, drawerTrigger);
  const busyNodesValue = page.locator('[data-stat-value="busy-nodes"]:visible');
    await expect(busyNodesValue).toBeVisible();

    // Initial terminal status should be idle (0 busy nodes).
    await expect(busyNodesValue.first()).toHaveText('0');
  });

  test('submitting a command transitions terminal to BUSY', async ({ page }) => {
    await page.goto('/');

    const terminalInput = page.getByPlaceholder(
      'Type a prompt for the active agent. Press Enter to send.'
    );
    const drawerTrigger = page.locator('[data-drawer-trigger="metadata"]');
    const busyNodesValue = page.locator('[data-stat-value="busy-nodes"]:visible');

    await expect(terminalInput).toBeEnabled();
    await openDrawerAndHealth(page, drawerTrigger);
    await expect(busyNodesValue.first()).toHaveText('0');
    await closeDrawer(page); // close drawer to keep workspace focused

    await terminalInput.fill('help');
    await terminalInput.press('Enter');

    await expect(terminalInput).toBeDisabled();
    await openDrawerAndHealth(page, drawerTrigger);
    await expect(busyNodesValue.first()).toHaveText('1', { timeout: 30_000 });
    await closeDrawer(page);
  });
});
