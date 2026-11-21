import { describe, expect, it } from 'vitest';
import { analyzeEvents } from './analyze';
import { rules } from '../rules';
import { cookie, makeEvent } from '../test-utils';

describe('analyzeEvents', () => {
  it('evaluates every registered rule', () => {
    const result = analyzeEvents({ events: [makeEvent()] });
    expect(result.evaluatedRules).toBe(rules.length);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('flags a deliberately bad document', () => {
    const event = makeEvent({
      url: 'http://app.example.com/login?token=abcdef123456789',
      pageUrl: 'http://app.example.com/login',
      pageOrigin: 'http://app.example.com',
      responseHeaders: { server: 'nginx/1.18.0', 'x-powered-by': 'Express' },
    });
    const result = analyzeEvents({
      events: [event],
      cookies: [
        cookie({ name: 'sid', httpOnly: false, secure: false, sameSite: 'unspecified' }),
        cookie({ name: 'prefs', httpOnly: false }),
      ],
      focus: 'all',
    });
    const ids = result.findings.map((finding) => finding.ruleId);
    expect(ids).toContain('cookie-session-js-readable');
    expect(ids).toContain('header-csp-missing');
    expect(ids).toContain('secret-in-url');
    expect(ids).toContain('server-version-disclosure');
    expect(ids).toContain('insecure-http');
    expect(result.score.score).toBeLessThan(60);
  });

  it('returns a perfect score for a hardened page', () => {
    const event = makeEvent({
      responseHeaders: {
        'content-security-policy':
          "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
        'strict-transport-security': 'max-age=63072000; includeSubDomains',
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'camera=()',
      },
    });
    const result = analyzeEvents({
      events: [event],
      cookies: [cookie()],
      focus: 'all',
    });
    expect(result.findings).toEqual([]);
    expect(result.score.score).toBe(100);
  });

  it('deduplicates findings across repeated requests', () => {
    const events = [makeEvent({ id: 'a' }), makeEvent({ id: 'b' })];
    const result = analyzeEvents({ events, focus: 'all' });
    const csp = result.findings.filter((finding) => finding.ruleId === 'header-csp-missing');
    expect(csp).toHaveLength(1);
  });

  it('skips document-only rules for API responses', () => {
    const result = analyzeEvents({
      events: [makeEvent({ resourceType: 'xhr', mimeType: 'application/json' })],
      focus: 'all',
    });
    expect(result.findings.some((finding) => finding.ruleId === 'header-csp-missing')).toBe(false);
  });

  it('tracks worst severity per host', () => {
    const result = analyzeEvents({ events: [makeEvent({ responseHeaders: {} })], focus: 'all' });
    expect(result.severityByHost['app.example.com']).toBe('high');
  });

  it('defaults to the four v1 attack classes and hides extended checks', () => {
    const result = analyzeEvents({ events: [makeEvent()] });
    const ids = result.findings.map((finding) => finding.ruleId);
    expect(ids).toContain('header-frame-options-missing');
    expect(ids).not.toContain('header-csp-missing');
    expect(result.findings.every((finding) => finding.attack && finding.confidence === 'high')).toBe(true);
  });
});
