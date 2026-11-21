import { describe, expect, it } from 'vitest';
import { buildHtmlReport, buildJsonReport, reportFileName } from './htmlReport';
import { makeContext } from '../test-utils';
import { rules } from '../rules';
import { toFinding } from '../rules/types';
import { scoreFindings } from '../core/score';
import { makeEvent } from '../test-utils';

const event = makeEvent();
const rule = rules.find((candidate) => candidate.id === 'header-csp-missing');
if (!rule) throw new Error('rule missing');
const finding = toFinding(rule, { key: 'csp', message: 'No CSP here' }, makeContext());
const score = scoreFindings([finding]);

describe('buildHtmlReport', () => {
  const html = buildHtmlReport({
    pageUrl: 'https://app.example.com/?token=abcdef123456789',
    generatedAt: Date.UTC(2024, 0, 1),
    score,
    findings: [finding],
    events: [event],
  });

  it('produces a complete standalone document', () => {
    expect(html.startsWith('<!doctype html>')).toBe(true);
    expect(html).toContain('NetXRay security report');
    expect(html.trimEnd().endsWith('</html>')).toBe(true);
  });

  it('loads nothing from the network', () => {
    expect(html).not.toMatch(/https?:\/\/(?!app\.example\.com)[^\s"'<>]+\.(js|css|png|woff2?)/);
    expect(html).not.toContain('<link rel="stylesheet"');
    expect(html).not.toContain('<script src=');
  });

  it('redacts secrets in the page URL', () => {
    expect(html).not.toContain('abcdef123456789');
  });

  it('contains the finding structure', () => {
    expect(html).toContain('What is it?');
    expect(html).toContain('How could an attacker use it?');
    expect(html).toContain('Content-Security-Policy');
  });

  it('escapes HTML in captured data', () => {
    const malicious = toFinding(
      rule,
      { key: 'xss', message: '<img src=x onerror=alert(1)>' },
      makeContext({ url: 'https://app.example.com/<script>alert(1)</script>' }),
    );
    const output = buildHtmlReport({
      pageUrl: 'https://app.example.com/',
      generatedAt: Date.UTC(2024, 0, 1),
      score,
      findings: [malicious],
      events: [],
    });
    // The payload may exist inside the JSON island only escaped as unicode.
    expect(output).not.toContain('<img src=x onerror=alert(1)>');
    expect(output).not.toContain('<script>alert(1)</script>');
    expect(output).toContain('\\u003c');
  });

  it('handles an empty page URL', () => {
    const output = buildHtmlReport({
      pageUrl: '',
      generatedAt: Date.UTC(2024, 0, 1),
      score,
      findings: [],
      events: [],
    });
    expect(output).toContain('NetXRay security report');
  });
});

describe('buildJsonReport', () => {
  it('emits a versioned report with masked evidence', () => {
    const json = JSON.parse(
      buildJsonReport({
        pageUrl: 'https://app.example.com/',
        generatedAt: Date.UTC(2024, 0, 1),
        score,
        findings: [{ ...finding, evidence: 'super-secret-token-value' }],
        events: [event],
      }),
    );
    expect(json.format).toBe('netxray-report@1');
    expect(json.events).toHaveLength(1);
    expect(json.findings[0].evidence).not.toBe('super-secret-token-value');
  });
});

describe('reportFileName', () => {
  it('uses an ISO timestamp and the requested extension', () => {
    const name = reportFileName('html', Date.UTC(2024, 0, 1, 2, 3, 4));
    expect(name).toBe('netxray-2024-01-01T02-03-04.html');
  });
});
