import { chromium, expect, test, type BrowserContext } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const extensionPath = resolve('dist');

/**
 * Loads the unpacked build into a persistent Chromium profile, exactly like a
 * developer following the README. DevTools panel content is extension UI, so
 * these tests drive the real built panel page.
 */
test.describe('built extension', () => {
  let context: BrowserContext;
  let extensionId: string;

  test.beforeAll(async () => {
    context = await chromium.launchPersistentContext('', {
      headless: false,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`,
        '--no-first-run',
        '--no-default-browser-check',
      ],
    });
    const existing = context.serviceWorkers()[0];
    const worker = existing ?? (await context.waitForEvent('serviceworker', { timeout: 20_000 }));
    extensionId = new URL(worker.url()).host;
  });

  test.afterAll(async () => {
    await context.close();
  });

  test('ships a minimal, documented MV3 manifest', async () => {
    const manifest = JSON.parse(await readFile(resolve(extensionPath, 'manifest.json'), 'utf8'));
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.devtools_page).toBe('devtools.html');
    expect(manifest.background.service_worker).toBe('background.js');
    expect(manifest.permissions.sort()).toEqual(['cookies', 'scripting', 'storage']);
    expect(manifest.optional_permissions).toEqual(['debugger']);
    expect(manifest.host_permissions).toEqual(['<all_urls>']);
    expect(manifest.content_security_policy.extension_pages).toContain("script-src 'self'");
  });

  test('starts the service worker and answers the typed ping', async () => {
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/panel.html`);
    const response = await page.evaluate(async () => chrome.runtime.sendMessage({ type: 'PING' }));
    expect(response).toEqual({ ok: true });
    await page.close();
  });

  test('panel renders the four views and the first-run tour', async () => {
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/panel.html`);
    await expect(page.getByText('Guided tour · 1 of 4')).toBeVisible();
    await expect(page.getByRole('button', { name: /^Timeline/ })).toBeVisible();
    await expect(page.getByRole('button', { name: /^Map/ })).toBeVisible();
    await expect(page.getByRole('button', { name: /^Security/ })).toBeVisible();
    await expect(page.getByRole('button', { name: /^Storage/ })).toBeVisible();
    await expect(page.getByText('Only on systems you own')).toBeVisible();
    await page.close();
  });

  test('guided tour can be completed and keyboard shortcuts switch views', async () => {
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/panel.html`);
    for (let step = 0; step < 3; step += 1) {
      await page.getByRole('button', { name: 'Next' }).click();
    }
    await page.getByRole('button', { name: 'Start exploring' }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);

    await page.keyboard.press('3');
    await expect(page.getByText(/Security score:/)).toBeVisible();
    await page.keyboard.press('4');
    await expect(page.getByRole('heading', { name: /Cookies/ })).toBeVisible();
    await page.keyboard.press('2');
    await expect(page.getByText('No domains mapped yet')).toBeVisible();
    await page.close();
  });

  test('export with an empty session explains how to capture', async () => {
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/panel.html`);
    const tour = page.getByRole('dialog');
    if (await tour.isVisible().catch(() => false)) {
      await page.getByRole('button', { name: 'Skip' }).click();
    }
    await page.getByText('Export ▾').click();
    await page.getByRole('button', { name: 'Shareable HTML report' }).click();
    await expect(page.getByRole('status')).toContainText('Nothing captured yet');
    await page.close();
  });

  test('background reads cookies for the demo origin', async () => {
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/panel.html`);
    // Set a cookie on the demo origin through a normal page first.
    const demo = await context.newPage();
    await demo.goto('http://localhost:4000/vulnerable/');
    const response = await page.evaluate(async () => {
      return chrome.runtime.sendMessage({ type: 'GET_COOKIES', url: 'http://localhost:4000/vulnerable/' });
    });
    const cookies = (response as { cookies: { name: string; httpOnly: boolean }[] }).cookies;
    const sid = cookies.find((cookie) => cookie.name === 'sid');
    expect(sid).toBeTruthy();
    expect(sid?.httpOnly).toBe(false); // deliberately insecure demo cookie
    await demo.close();
    await page.close();
  });
});
