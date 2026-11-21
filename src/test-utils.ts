import { normalizeHarEntry, type HarEntry } from './core/har';
import type {
  CookieObservation,
  NetworkEvent,
  PageContext,
  Remediation,
  Severity,
} from './core/types';
import { normalizeTimings } from './core/timings';
import { collectJwts } from './rules/lib/jwts';
import { queryOf } from './core/url';
import type { Rule, RuleContext } from './rules/types';

export function makeEvent(overrides: Partial<NetworkEvent> = {}): NetworkEvent {
  const base: NetworkEvent = {
    id: 'evt-1',
    startedAt: 1_700_000_000_000,
    startOffset: 0,
    url: 'https://app.example.com/dashboard',
    pageUrl: 'https://app.example.com/',
    pageOrigin: 'https://app.example.com',
    method: 'GET',
    status: 200,
    statusText: 'OK',
    mimeType: 'text/html',
    resourceType: 'document',
    httpVersion: 'h2',
    fromCache: false,
    requestHeaders: {},
    responseHeaders: {},
    setCookie: [],
    requestCookies: [],
    query: {},
    sizes: { requestHeaders: 100, requestBody: 0, responseHeaders: 200, responseBody: 1000, total: 1300 },
    timings: normalizeTimings({ blocked: 1, dns: 5, connect: 20, ssl: 12, send: 1, wait: 40, receive: 8 }),
    bodyCaptured: false,
    cookiesObserved: [],
  };
  const merged = { ...base, ...overrides };
  // Derive the query map from the (possibly overridden) URL so rules see it.
  if (!overrides.query) merged.query = queryOf(merged.url);
  return merged;
}

export function makeContext(event: Partial<NetworkEvent> = {}, cookies: CookieObservation[] = []): RuleContext {
  const fullEvent = makeEvent(event);
  const page: PageContext = {
    pageUrl: fullEvent.pageUrl,
    pageOrigin: fullEvent.pageOrigin,
    isHttps: fullEvent.pageUrl.startsWith('https://'),
  };
  return { event: fullEvent, page, cookies, jwts: collectJwts(fullEvent) };
}

export function cookie(overrides: Partial<CookieObservation> = {}): CookieObservation {
  return {
    name: 'sid',
    value: 'super-secret-session-value',
    domain: 'app.example.com',
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
    session: true,
    hostOnly: true,
    ...overrides,
  };
}

/** Normalizes a raw HAR entry through the same path production uses. */
export function fromHar(entry: Partial<HarEntry>): NetworkEvent {
  const har: HarEntry = {
    startedDateTime: '2024-01-01T00:00:00.000Z',
    time: 100,
    request: { method: 'GET', url: 'https://app.example.com/', headers: [] },
    response: { status: 200, statusText: 'OK', headers: [], content: { size: 10, mimeType: 'text/html' } },
    timings: { blocked: 0, dns: 1, connect: 2, ssl: 1, send: 1, wait: 5, receive: 1 },
    _resourceType: 'document',
    ...entry,
  };
  return normalizeHarEntry(har, { pageUrl: har.request.url });
}

/** Asserts a rule fires, and returns the hits for further checks. */
export function evaluateRule(rule: Rule, ctx: RuleContext) {
  return rule.evaluate(ctx);
}

export function b64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** Builds an unsigned-looking JWT for rule tests. */
export function makeJwt(header: Record<string, unknown>, payload: Record<string, unknown>, signature = 'sig'): string {
  return `${b64url(header)}.${b64url(payload)}.${signature}`;
}

export const severities: Severity[] = ['info', 'low', 'medium', 'high'];

export const frameworks: Remediation['framework'][] = ['express', 'nextjs', 'nginx'];
