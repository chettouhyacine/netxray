import { describe, expect, it } from 'vitest';
import {
  cookie,
  makeEvent,
  makeJwt,
} from '../test-utils';
import { analyzeEvents } from './analyze';

/**
 * Labelled precision/recall benchmark for the four v1 attack classes.
 *
 * The vulnerable profile has one deliberate example of every v1 claim. The
 * hardened profile is the same app after remediation. Precision and recall are
 * asserted against the labels, so a noisy new rule or a silent regression
 * fails the build instead of shipping.
 */
const PAGE = 'https://app.example.com/';
const HARDENED_HEADERS: Record<string, string> = {
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-frame-options': 'DENY',
};

const EXPECTED = [
  'cookie-session-js-readable',
  'cookie-missing-secure',
  'header-frame-options-missing',
  'cors-reflected-origin',
  'cors-wildcard-credentials',
  'secret-in-url',
  'secret-in-response',
  'jwt-alg-none',
  'jwt-sensitive-payload',
] as const;

function vulnerableTraffic() {
  const doc = makeEvent({
    id: 'doc',
    url: PAGE,
    pageUrl: PAGE,
    pageOrigin: 'https://app.example.com',
    responseHeaders: {},
  });
  const reflected = makeEvent({
    id: 'cors-reflected',
    url: 'https://api.example.com/me',
    pageUrl: PAGE,
    resourceType: 'xhr',
    mimeType: 'application/json',
    requestHeaders: { origin: 'https://evil.example' },
    responseHeaders: {
      'access-control-allow-origin': 'https://evil.example',
      'access-control-allow-credentials': 'true',
    },
  });
  const wildcard = makeEvent({
    id: 'cors-wildcard',
    url: 'https://api.example.com/public',
    pageUrl: PAGE,
    resourceType: 'xhr',
    responseHeaders: {
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
    },
  });
  const tokenInUrl = makeEvent({
    id: 'token-url',
    url: 'https://app.example.com/callback?access_token=super-secret-token-value',
    pageUrl: PAGE,
    resourceType: 'xhr',
  });
  const leakedKey = makeEvent({
    id: 'leaked-key',
    url: 'https://app.example.com/api/keys',
    pageUrl: PAGE,
    resourceType: 'xhr',
    mimeType: 'application/json',
    responseBodyText: '{"awsAccessKeyId":"AKIAIOSFODNN7EXAMPLE"}',
  });
  const unsignedJwt = makeEvent({
    id: 'unsigned-jwt',
    url: 'https://app.example.com/api/token',
    pageUrl: PAGE,
    resourceType: 'xhr',
    mimeType: 'application/json',
    responseBodyText: `{"token":"${makeJwt({ alg: 'none' }, { sub: 'demo', password: 'hunter2' }, '')}"}`,
  });
  return [doc, reflected, wildcard, tokenInUrl, leakedKey, unsignedJwt];
}

function hardenedTraffic() {
  const doc = makeEvent({
    id: 'doc-fixed',
    url: PAGE,
    pageUrl: PAGE,
    pageOrigin: 'https://app.example.com',
    responseHeaders: HARDENED_HEADERS,
  });
  const api = makeEvent({
    id: 'api-fixed',
    url: 'https://app.example.com/api/me',
    pageUrl: PAGE,
    resourceType: 'xhr',
    mimeType: 'application/json',
    requestHeaders: { origin: 'https://app.example.com' },
    responseHeaders: {
      'access-control-allow-origin': 'https://app.example.com',
      'cache-control': 'private, no-store',
    },
    responseBodyText:
      '{"user":{"id":"demo"},"token":"' +
      makeJwt({ alg: 'HS256' }, { sub: 'demo', iat: 1_700_000_000, exp: 1_700_000_900 }, 'signature') +
      '"}',
  });
  return [doc, api];
}

describe('v1 attack benchmark', () => {
  it('detects every labelled attack with no extra claims', () => {
    const result = analyzeEvents({
      events: vulnerableTraffic(),
      cookies: [cookie({ name: 'sid', httpOnly: false, secure: false })],
    });
    const found = new Set(result.findings.map((finding) => finding.ruleId));
    const expected = new Set<string>(EXPECTED);

    const truePositives = [...found].filter((id) => expected.has(id));
    const precision = found.size === 0 ? 1 : truePositives.length / found.size;
    const recall = truePositives.length / expected.size;

    expect(recall).toBe(1);
    expect(precision).toBe(1);
    expect(result.findings.every((finding) => finding.confidence === 'high')).toBe(true);
  });

  it('reports nothing on the hardened profile', () => {
    const result = analyzeEvents({
      events: hardenedTraffic(),
      cookies: [cookie()],
    });
    expect(result.findings).toEqual([]);
    expect(result.score.score).toBe(100);
  });

  it('does not claim a session attack for preference cookies', () => {
    const result = analyzeEvents({
      events: [
        makeEvent({
          responseHeaders: HARDENED_HEADERS,
        }),
      ],
      cookies: [cookie({ name: 'prefs', httpOnly: false, secure: false, sameSite: 'unspecified' })],
    });
    expect(result.findings).toEqual([]);
  });

  it('still catches framing controls that allow any origin', () => {
    for (const csp of ['frame-ancestors *', 'frame-ancestors https:']) {
      const result = analyzeEvents({
        events: [makeEvent({ responseHeaders: { 'content-security-policy': csp } })],
      });
      expect(result.findings.map((finding) => finding.ruleId)).toContain('header-frame-options-missing');
    }
  });

  it('does not treat a same-origin CORS echo or a short signed JWT as an attack', () => {
    const sameOrigin = makeEvent({
      url: 'https://app.example.com/api/me',
      pageUrl: PAGE,
      resourceType: 'xhr',
      mimeType: 'application/json',
      requestHeaders: { origin: 'https://app.example.com' },
      responseHeaders: { 'access-control-allow-origin': 'https://app.example.com' },
    });
    const signedJwt = makeEvent({
      url: 'https://app.example.com/api/token',
      pageUrl: PAGE,
      resourceType: 'xhr',
      mimeType: 'application/json',
      responseBodyText: makeJwt({ alg: 'HS256' }, { sub: 'demo', iat: 1_700_000_000, exp: 1_700_000_900 }),
    });
    const result = analyzeEvents({
      events: [sameOrigin, signedJwt],
      cookies: [cookie()],
    });
    expect(result.findings).toEqual([]);
  });
});
