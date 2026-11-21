import { describe, expect, it } from 'vitest';
import { exportHar, groupByDomain, sessionBounds, summarizeSession, withSessionOffsets } from './session';
import { makeEvent } from '../test-utils';

const events = [
  makeEvent({ id: '1', startedAt: 1000, pageOrigin: 'https://app.example.com', url: 'https://app.example.com/', sizes: { requestHeaders: 10, requestBody: 0, responseHeaders: 10, responseBody: 100, total: 120 } }),
  makeEvent({ id: '2', startedAt: 1500, url: 'https://cdn.other.com/lib.js', resourceType: 'script', sizes: { requestHeaders: 10, requestBody: 0, responseHeaders: 10, responseBody: 50, total: 70 } }),
  makeEvent({ id: '3', startedAt: 2000, url: 'https://cdn.other.com/logo.png', resourceType: 'image', sizes: { requestHeaders: 10, requestBody: 0, responseHeaders: 10, responseBody: 20, total: 40 } }),
];

describe('sessionBounds', () => {
  it('finds the first start and last end', () => {
    const bounds = sessionBounds(events);
    expect(bounds.start).toBe(1000);
    expect(bounds.end).toBeGreaterThan(2000);
  });

  it('handles an empty session', () => {
    expect(sessionBounds([]).end).toBeGreaterThan(0);
  });
});

describe('withSessionOffsets', () => {
  it('rebases every event on the first request', () => {
    const rebased = withSessionOffsets(events);
    expect(rebased[0]?.startOffset).toBe(0);
    expect(rebased[2]?.startOffset).toBe(1000);
  });
});

describe('summarizeSession', () => {
  it('groups bytes and requests per domain', () => {
    const summary = summarizeSession(events);
    expect(summary.requestCount).toBe(3);
    expect(summary.totalBytes).toBe(230);
    expect(summary.pageUrl).toBe('https://app.example.com/');
    const cdn = summary.domains.find((domain) => domain.host === 'cdn.other.com');
    expect(cdn?.requestCount).toBe(2);
    expect(cdn?.isThirdParty).toBe(true);
  });

  it('applies worst severity per domain', () => {
    const summary = summarizeSession(events, new Map([['cdn.other.com', 'high' as const]]));
    expect(summary.domains.find((domain) => domain.host === 'cdn.other.com')?.worstSeverity).toBe('high');
  });
});

describe('groupByDomain', () => {
  it('groups events by hostname', () => {
    expect(groupByDomain(events).get('cdn.other.com')).toHaveLength(2);
  });
});

describe('exportHar', () => {
  it('produces valid HAR 1.2 JSON', () => {
    const har = JSON.parse(exportHar(events, 'https://app.example.com/'));
    expect(har.log.version).toBe('1.2');
    expect(har.log.entries).toHaveLength(3);
    expect(har.log.entries[0].response.status).toBe(200);
    expect(har.log.entries[0].timings.connect).toBe(20);
    expect(har.log.pages[0].title).toBe('https://app.example.com/');
  });

  it('handles an empty session', () => {
    const har = JSON.parse(exportHar([], ''));
    expect(har.log.entries).toEqual([]);
  });
});
