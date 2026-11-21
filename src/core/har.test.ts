import { describe, expect, it } from 'vitest';
import { isTextualMime, normalizeHarEntry, parsedSetCookies, type HarEntry } from './har';
import { fromHar } from '../test-utils';

describe('normalizeHarEntry', () => {
  it('normalizes a typical entry', () => {
    const event = fromHar({
      request: {
        method: 'post',
        url: 'https://api.example.com/login?next=%2Fapp',
        headers: [
          { name: 'Cookie', value: 'sid=abc' },
          { name: 'Content-Type', value: 'application/json' },
        ],
        postData: { mimeType: 'application/json', text: '{"user":"a"}' },
        headersSize: 100,
        bodySize: 12,
      },
      response: {
        status: 201,
        statusText: 'Created',
        headers: [
          { name: 'Set-Cookie', value: 'sid=new; HttpOnly' },
          { name: 'Cache-Control', value: 'no-store' },
        ],
        content: { size: 50, mimeType: 'application/json', text: '{"ok":true}' },
        headersSize: 80,
        bodySize: 50,
      },
      serverIPAddress: '203.0.113.7',
      timings: { blocked: 1, dns: 2, connect: 10, ssl: 4, send: 1, wait: 20, receive: 5 },
    });

    expect(event.method).toBe('POST');
    expect(event.status).toBe(201);
    expect(event.query.next).toEqual(['/app']);
    expect(event.requestCookies[0]?.name).toBe('sid');
    expect(event.setCookie).toEqual(['sid=new; HttpOnly']);
    expect(event.responseBodyText).toBe('{"ok":true}');
    expect(event.requestBodyText).toBe('{"user":"a"}');
    expect(event.timings.tcp).toBe(6);
    expect(event.serverIpAddress).toBe('203.0.113.7');
    expect(event.sizes.total).toBe(242);
    expect(event.pageOrigin).toBe('https://api.example.com');
  });

  it('decodes base64 bodies', () => {
    const text = 'hello netxray';
    const event = fromHar({
      response: {
        status: 200,
        headers: [],
        content: {
          size: 13,
          mimeType: 'text/plain',
          text: Buffer.from(text, 'utf8').toString('base64'),
          encoding: 'base64',
        },
      },
    });
    expect(event.responseBodyText).toBe(text);
    expect(event.bodyCaptured).toBe(true);
  });

  it('computes offsets relative to the session start', () => {
    const entry: HarEntry = {
      startedDateTime: '2024-01-01T00:00:01.000Z',
      request: { method: 'GET', url: 'https://app.example.com/a', headers: [] },
      response: { status: 200, headers: [] },
      timings: {},
    };
    const event = normalizeHarEntry(entry, {
      pageUrl: 'https://app.example.com/',
      sessionStart: Date.parse('2024-01-01T00:00:00.000Z'),
    });
    expect(event.startOffset).toBe(1000);
  });

  it('marks cached responses', () => {
    const event = fromHar({ cache: { beforeRequest: { expires: '2024-01-01' } } });
    expect(event.fromCache).toBe(true);
  });

  it('throws without a URL', () => {
    expect(() =>
      normalizeHarEntry({ request: { method: 'GET', url: '' } } as unknown as HarEntry, { pageUrl: '' }),
    ).toThrowError();
  });
});

describe('helpers', () => {
  it('parses Set-Cookie entries on demand', () => {
    const event = fromHar({ response: { status: 200, headers: [{ name: 'Set-Cookie', value: 'a=1; Secure' }] } });
    expect(parsedSetCookies(event)[0]?.attributes.secure).toBe(true);
  });

  it('detects textual mime types', () => {
    expect(isTextualMime('application/json')).toBe(true);
    expect(isTextualMime('text/html')).toBe(true);
    expect(isTextualMime('image/png')).toBe(false);
  });
});
