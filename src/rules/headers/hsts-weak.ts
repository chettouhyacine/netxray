import { headerRemediation } from '../lib/remediation';
import type { Rule } from '../types';

const MIN_MAX_AGE = 15_552_000; // 180 days

const rule: Rule = {
  id: 'header-hsts-weak',
  severity: 'low',
  title: 'HSTS max-age is too short',
  what: 'Strict-Transport-Security is present but covers less than 180 days, or does not include subdomains.',
  why: 'HSTS protection only lasts as long as max-age. A short window means the browser forgets the policy and becomes downgradable again, and without includeSubDomains the protection stops at the exact hostname.',
  attack:
    'The attacker waits until the short HSTS window expires, then intercepts the first http:// request to the site or to an unprotected subdomain and serves a phishing page.',
  tags: ['headers', 'transport'],
  appliesTo: 'document',
  remediation: headerRemediation({
    header: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains',
  }),
  evaluate(ctx) {
    const value = ctx.event.responseHeaders['strict-transport-security'];
    if (!value) return [];
    const maxAgeMatch = /max-age\s*=\s*(\d+)/i.exec(value);
    const maxAge = maxAgeMatch?.[1] ? Number(maxAgeMatch[1]) : 0;
    const includesSubdomains = /includeSubDomains/i.test(value);
    const hits = [];
    if (maxAge < MIN_MAX_AGE) {
      hits.push({
        key: 'max-age',
        message: `HSTS max-age is ${maxAge} seconds (< 180 days).`,
        detail: 'Use at least 63072000 seconds (two years) once you are confident every subdomain is HTTPS-ready.',
        evidence: value,
      });
    }
    if (!includesSubdomains) {
      hits.push({
        key: 'subdomains',
        message: 'HSTS does not include subdomains.',
        detail: 'Subdomains can still be downgraded to http:// and used to attack the main origin.',
        evidence: value,
      });
    }
    return hits;
  },
};

export default rule;
