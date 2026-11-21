import { expect, test } from '@playwright/test';

const VULNERABLE = 'http://localhost:4000/vulnerable/';
const FIXED = 'http://localhost:4000/fixed/';

test.describe('demo app', () => {
  test('vulnerable mode exposes the intended insecure behaviour', async ({ request }) => {
    const page = await request.get(VULNERABLE);
    expect(page.status()).toBe(200);
    expect(page.headers()['content-security-policy']).toBeUndefined();
    expect(page.headers()['x-frame-options']).toBeUndefined();
    expect(page.headers()['server']).toBe('nginx/1.18.0');
    const setCookie = (page.headersArray() ?? [])
      .filter((header) => header.name.toLowerCase() === 'set-cookie')
      .map((header) => header.value)
      .join('\n');
    expect(setCookie).toContain('sid=');
    expect(setCookie.toLowerCase()).not.toContain('httponly');

    const api = await request.get(`${VULNERABLE}api/me`);
    expect(api.headers()['access-control-allow-origin']).toBe('*');
    expect(api.headers()['access-control-allow-credentials']).toBe('true');
  });

  test('fixed mode sets hardened cookies and headers', async ({ request }) => {
    const page = await request.get(FIXED);
    expect(page.headers()['content-security-policy']).toContain("default-src 'self'");
    expect(page.headers()['x-frame-options']).toBe('DENY');
    expect(page.headers()['x-content-type-options']).toBe('nosniff');
    expect(page.headers()['strict-transport-security']).toContain('max-age=63072000');
    const setCookie = (page.headersArray() ?? [])
      .filter((header) => header.name.toLowerCase() === 'set-cookie')
      .map((header) => header.value)
      .join('\n');
    expect(setCookie.toLowerCase()).toContain('httponly');
    expect(setCookie.toLowerCase()).toContain('samesite=lax');
  });

  test('verbose errors are only present in vulnerable mode', async ({ request }) => {
    const vulnerable = await request.get(`${VULNERABLE}api/boom`);
    expect(vulnerable.status()).toBe(500);
    expect(await vulnerable.text()).toContain('node_modules');

    const fixed = await request.get(`${FIXED}api/boom`);
    expect(fixed.status()).toBe(500);
    expect(await fixed.text()).not.toContain('node_modules');
  });

  test('credentials leak only in vulnerable mode', async ({ request }) => {
    const vulnerable = await request.get(`${VULNERABLE}api/credentials`);
    const body = await vulnerable.text();
    expect(body).toContain('AKIAIOSFODNN7EXAMPLE');
    expect(body).toContain('sk_live_');

    const fixed = await request.get(`${FIXED}api/credentials`);
    expect(await fixed.text()).not.toContain('AKIA');
  });

  test('tokens differ between modes', async ({ request }) => {
    const vulnerable = await request.get(`${VULNERABLE}api/token`);
    const bad = (await vulnerable.json()) as { token: string };
    const header = JSON.parse(Buffer.from(bad.token.split('.')[0] ?? '', 'base64url').toString());
    expect(header.alg).toBe('none');

    const fixed = await request.get(`${FIXED}api/token`);
    const good = (await fixed.json()) as { token: string; expiresIn: number };
    expect(good.expiresIn).toBe(900);
    const fixedHeader = JSON.parse(Buffer.from(good.token.split('.')[0] ?? '', 'base64url').toString());
    expect(fixedHeader.alg).toBe('HS256');
  });
});
