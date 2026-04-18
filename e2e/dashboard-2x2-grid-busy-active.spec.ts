import { expect, test, type Page } from '@playwright/test';

async function addAgentsToFour(page: Page) {
  const addButton = page.getByRole('button', { name: 'Add Agent' });
  for (let i = 0; i < 3; i += 1) {
    await addButton.click();
  }
}

async function observedBusyThenActive(page: Page, sessionId: string, timeoutMs = 90_000): Promise<boolean> {
  return page.evaluate(
    ({ id, timeout }) =>
      new Promise<boolean>((resolve) => {
        const started = Date.now();
        let sawBusy = false;

        const tick = () => {
          const pane = document.querySelector(`[data-session-id="${id}"]`);
          const state = pane?.getAttribute('data-session-state') ?? '';

          if (state === 'busy') {
            sawBusy = true;
          }

          if (sawBusy && state === 'active') {
            resolve(true);
            return;
          }

          if (Date.now() - started >= timeout) {
            resolve(false);
            return;
          }

          requestAnimationFrame(tick);
        };

        tick();
      }),
    { id: sessionId, timeout: timeoutMs }
  );
}

test.describe('Dashboard 2x2 grid busy/active transitions', () => {
  test('spawns 4 agents and verifies BUSY -> ACTIVE across all panes', async ({ page }) => {
    test.setTimeout(180_000);
    await page.goto('/');
    const activeTerminals = page.locator('[data-session-state="active"]');
    const terminalInput = page.getByPlaceholder(
      'Type a prompt for the active agent. Press Enter to send.'
    );

    await addAgentsToFour(page);

    await expect(page.locator('button:has-text("AGENT-1")').first()).toBeVisible();
    await expect(page.locator('button:has-text("AGENT-2")').first()).toBeVisible();
    await expect(page.locator('button:has-text("AGENT-3")').first()).toBeVisible();
    await expect(page.locator('button:has-text("AGENT-4")').first()).toBeVisible();

    await expect(activeTerminals).toHaveCount(4);

    for (const sessionId of ['AGENT-1', 'AGENT-2', 'AGENT-3', 'AGENT-4']) {
      const sessionButton = page.locator(`button:has-text("${sessionId}")`).first();
      await sessionButton.click();
      await expect(page.getByText(`Active Session: ${sessionId}`).first()).toBeVisible();

      await expect(terminalInput).toBeEnabled();
      await terminalInput.fill('help');
      await terminalInput.press('Enter');

      const transitioned = await observedBusyThenActive(page, sessionId, 90_000);
      expect(transitioned).toBeTruthy();
    }

    await expect(activeTerminals).toHaveCount(4, { timeout: 90_000 });
  });
});
