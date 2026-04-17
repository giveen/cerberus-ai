import { expect, test } from '@playwright/test';

test.describe('Dashboard sanity', () => {
  test('renders core layout regions', async ({ page }) => {
    await page.goto('/');

    const sidebar = page.getByText('OPS SIDEBAR');
    const terminalInput = page.getByPlaceholder(
      'Type a prompt for the active agent. Press Enter to send.'
    );
    const runButton = page.getByRole('button', { name: 'Run' });
    const stopButton = page.getByRole('button', { name: 'Stop' });
    const terminalPanel = page.getByText('Standing by for a prompt or command.');
    const busyNodesLabel = page.getByText('BUSY NODES');

    await expect(sidebar).toBeVisible();
    await expect(terminalInput).toBeVisible();
    await expect(runButton).toBeVisible();
    await expect(stopButton).toBeVisible();
    await expect(terminalPanel).toBeVisible();
    await expect(busyNodesLabel).toBeVisible();

    // Initial terminal status should be idle (0 busy nodes).
    await expect(
      busyNodesLabel.locator('xpath=following-sibling::*[1]')
    ).toHaveText('0');
  });

  test('submitting a command transitions terminal to BUSY', async ({ page }) => {
    await page.goto('/');

    const terminalInput = page.getByPlaceholder(
      'Type a prompt for the active agent. Press Enter to send.'
    );
    const busyNodesLabel = page.getByText('BUSY NODES');
    const busyNodesValue = busyNodesLabel.locator('xpath=following-sibling::*[1]');

    await expect(terminalInput).toBeEnabled();
    await expect(busyNodesValue).toHaveText('0');

    await terminalInput.fill('help');
    await terminalInput.press('Enter');

    await expect(terminalInput).toBeDisabled();
    await expect(busyNodesValue).toHaveText('1', { timeout: 30_000 });
  });
});
