import { describe, expect, it } from 'vitest';
import { analyzeEvents } from './analyze';
import { importHar } from './harImport';
import type { HarEntry } from './har';

function entry(overrides: Partial<HarEntry> = {}): HarEntry {
  return {
    startedDateTime: '2026-01-01T00:00:00.000Z',
    time: 40,
    request: { method: 'GET', url: 'https://app.example.com/', headers: [] },
    response: {
      status: 200,
      statusText: 'OK',
      headers: [{ name: 'content-type', value: 'text/html' }],
      content: { size: 20, mimeType: 'text/html', text: '<html></html>' },
    },
    timings: { wait: 10, receive: 5 },
    _resourceType: 'document',
    ...overrides,
  };
}

function har(entries: unknown[]) {
  return JSON.stringify({ log: { version: '1.2', entries } });
}

describe('importHar', () => {
  it('normalizes entries, page URL and cookies from another browser', () => {
    const result = importHar(
      har([
        entry({
          response: {
            status: 200,
            statusText: 'OK',
            headers: [{ name: 'content-type', value: 'text/html' }],
            content: { size: 20, mimeType: 'text/html', text: '<html></html>' },
            cookies: [
              {
                name: 'sid',
                value: 'abc',
                domain: '.app.example.com',
                path: '/',
                httpOnly: false,
                secure: false,
                sameSite: 'None',
              },
            ],
          },
        }),
        entry({
          startedDateTime: '2026-01-01T00:00:01.000Z',
          request: { method: 'GET', url: 'https://app.example.com/api', headers: [] },
          response: {
            status: 200,
            statusText: 'OK',
            headers: [],
            content: { size: 5, mimeType: 'application/json', text: '{"ok":true}' },
          },
          _resourceType: 'xhr',
        }),
      ]),
    );

    expect(result.events).toHaveLength(2);
    expect(result.pageUrl).toBe('https://app.example.com/');
    expect(result.skipped).toBe(0);
    const sid = result.cookies.find((cookie) => cookie.name === 'sid');
    expect(sid?.sameSite).toBe('no_restriction');
    expect(sid?.hostOnly).toBe(false);
    expect(sid?.session).toBe(true);
    expect(result.events[1]?.startOffset).toBe(1000);
  });

  it('runs the same v1 analysis on an imported capture', () => {
    const result = importHar(
      har([
        entry({
          response: {
            status: 200,
            statusText: 'OK',
            headers: [{ name: 'content-type', value: 'text/html' }],
            content: { size: 20, mimeType: 'text/html', text: '<html></html>' },
          },
        }),
      ]),
    );
    const analysis = analyzeEvents({ events: result.events, cookies: result.cookies });
    expect(analysis.findings.map((finding) => finding.ruleId)).toContain('header-frame-options-missing');
  });

  it('counts entries without a URL as skipped', () => {
    const result = importHar(
      har([
        entry(),
        entry({ request: { method: 'GET', url: '', headers: [] } }),
      ]),
    );
    expect(result.events).toHaveLength(1);
    expect(result.skipped).toBe(1);
  });

  it('rejects unusable files with a clear message', () => {
    expect(() => importHar('not json')).toThrow(/not valid JSON/);
    expect(() => importHar(JSON.stringify({ log: { entries: [] } }))).toThrow(/No HAR entries/);
    expect(() =>
      importHar(JSON.stringify({ log: { entries: [{ request: { url: '' } }] } })),
    ).toThrow(/no requests with a URL/i);
  });
});
