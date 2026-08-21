const { test, expect } = require('@playwright/test');

test.describe('Pipeline Guard browser smoke test', () => {
  test('runs the built-in repository demo and manages a suppression', async ({ page }) => {
    const pageErrors = [];
    page.on('pageerror', error => pageErrors.push(error.message));

    await page.goto('/');

    await expect(page).toHaveTitle(/PipelineGuard/i);
    await expect(page.locator('.privacy-pill')).toContainText('Local-first');
    await expect(page.locator('#scoreValue')).toHaveText('—');
    await expect(page.locator('#runDemoBtn')).toBeVisible();

    // Run the product's built-in deterministic risky-repository demo.
    await page.locator('#runDemoBtn').click();

    await expect(page.locator('#repoCard')).toBeVisible();
    await expect(page.locator('#repoName')).toHaveText('PipelineGuard-60-second-demo.zip');

    // A real scan should replace the initial score and produce actionable findings.
    await expect(page.locator('#scoreValue')).not.toHaveText('—');
    const score = Number(await page.locator('#scoreValue').textContent());
    expect(Number.isFinite(score)).toBeTruthy();
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThan(100);

    const findings = page.locator('#findings article.finding');
    await expect(findings.first()).toBeVisible();
    expect(await findings.count()).toBeGreaterThan(0);

    const activeFindingCount = Number(await page.locator('#allBadge').textContent());
    expect(activeFindingCount).toBeGreaterThan(0);

    // Report/export actions should become available after a successful scan.
    await expect(page.locator('#copyBtn')).toBeEnabled();
    await expect(page.locator('#exportBtn')).toBeEnabled();

    // Exercise first-class false-positive / exception management.
    const suppressButton = page.locator('.suppress-btn').first();
    await expect(suppressButton).toBeVisible();
    await suppressButton.click();

    await expect(page.locator('#suppressDialog')).toBeVisible();
    await expect(page.locator('#suppressFindingTitle')).not.toBeEmpty();

    await page.locator('#suppressReason').fill(
      'Playwright CI verifies the auditable suppression workflow.'
    );

    // The application supplies a future default expiration date.
    const expiry = await page.locator('#suppressExpiry').inputValue();
    expect(expiry).toMatch(/^\d{4}-\d{2}-\d{2}$/);

    await page.locator('#suppressForm button[type="submit"]').click();

    await expect(page.locator('#suppressDialog')).not.toBeVisible();
    await expect(page.locator('#suppressionTopCount')).toHaveText('1');
    await expect(page.locator('#suppressedBadge')).toHaveText('1');

    // Suppressed findings remain reviewable rather than disappearing.
    await page.locator('[data-filter="suppressed"]').click();
    const suppressedFinding = page.locator('#findings article.finding.is-suppressed').first();
    await expect(suppressedFinding).toBeVisible();
    await expect(suppressedFinding).toContainText(
      'Playwright CI verifies the auditable suppression workflow.'
    );

    expect(pageErrors, `Browser page errors: ${pageErrors.join(' | ')}`).toEqual([]);
  });
});
