import { hostOf, isThirdParty, isLocalHost } from '../../core/url';
import { remediation } from '../lib/remediation';
import { trackerForHost } from '../lib/trackers';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'third-party-unknown',
  severity: 'info',
  title: 'Request goes to a third-party origin',
  what: 'The page loaded a resource or called an API on a domain outside its own registrable domain.',
  why: 'Every third-party origin is a trust decision: it sees the request URL and headers, can change its response at any time, and can disappear or be compromised. An inventory is the first step to a tight CSP and a shorter supply chain.',
  attack:
    'An attacker compromises a small CDN the team forgot about, replaces a script with malicious code, and gets full DOM access on every page that loads it.',
  tags: ['third-party', 'supply-chain'],
  appliesTo: 'request',
  remediation: remediation(
    `// Express: allow-list third parties in CSP so new ones are deliberate
res.setHeader(
  'Content-Security-Policy',
  "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; connect-src 'self' https://api.example.com",
);`,
    `// next.config.mjs
const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value:
              "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; connect-src 'self'",
          },
        ],
      },
    ];
  },
};
export default nextConfig;`,
    `# nginx: enumerate origins explicitly, never use *
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net" always;`,
  ),
  evaluate(ctx) {
    const host = hostOf(ctx.event.url);
    if (!host || isLocalHost(host)) return [];
    if (!isThirdParty(ctx.event.url, ctx.event.pageOrigin)) return [];
    if (trackerForHost(host)) return [];
    return [
      {
        key: `origin:${host}`,
        message: `Request to third-party host ${host}.`,
        detail: `Type: ${ctx.event.resourceType}. Confirm this origin is expected and allow-listed in CSP.`,
      },
    ];
  },
};

export default rule;
