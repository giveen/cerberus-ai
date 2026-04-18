import { expect, test, type Locator, type Page } from '@playwright/test';

async function openDrawer(page: Page, drawerTrigger: Locator) {
  await drawerTrigger.click();
}

async function openOperationalControls(page: Page) {
  await page.getByText('Operational Controls').click();
}

test.describe('Intel Drawer persistence and layout', () => {
  test('persists operational toggle values across refresh', async ({ page }) => {
    await page.goto('/');

    const drawerTrigger = page.locator('[data-drawer-trigger="metadata"]');
    const verboseBadge = page.locator('[data-control-value="verbose_logs"]');
    const verboseToggle = page.locator('[data-control-toggle="verbose_logs"]');

    await openDrawer(page, drawerTrigger);
    await openOperationalControls(page);

    await expect(verboseBadge).toBeVisible();
    const initialValue = (await verboseBadge.textContent())?.trim() ?? '';

    await verboseToggle.click();
    await expect(verboseBadge).not.toHaveText(initialValue);

    const updatedValue = (await verboseBadge.textContent())?.trim() ?? '';

    await page.reload();
    await openDrawer(page, drawerTrigger);
    await openOperationalControls(page);

    await expect(verboseBadge).toHaveText(updatedValue);
  });

  test('keeps workspace logs unobscured when drawer is open', async ({ page }) => {
    await page.goto('/');

    const drawerTrigger = page.locator('[data-drawer-trigger="metadata"]');
    const drawerContent = page.locator('[data-intel-drawer="content"]');
    const workspaceShell = page.locator('[data-workspace-shell="true"]');

    await openDrawer(page, drawerTrigger);

    await expect(drawerContent).toBeVisible();
    await expect(workspaceShell).toBeVisible();

    const geometry = await page.evaluate(() => {
      const drawer = document.querySelector('[data-intel-drawer="content"]') as HTMLElement | null;
      const workspace = document.querySelector('[data-workspace-shell="true"]') as HTMLElement | null;
      if (!drawer || !workspace) {
        return null;
      }
      const drawerRect = drawer.getBoundingClientRect();
      const workspaceRect = workspace.getBoundingClientRect();
      return {
        drawerRight: drawerRect.right,
        workspaceLeft: workspaceRect.left,
      };
    });

    expect(geometry).not.toBeNull();
    expect((geometry?.drawerRight ?? 0) <= (geometry?.workspaceLeft ?? 0) + 1).toBeTruthy();
  });
});
