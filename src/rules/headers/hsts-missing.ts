import { hasHeader } from '../../core/headers';
import { headerRemediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'header-hsts-missing',
  severity: 'medium',
  title: 'No HTTP Strict Transport Security',
  what: 'The HTTPS page does not send a Strict-Transport-Security header, so the browser will happily try http:// for this host next time.',
  why: 'HSTS tells the browser to remember that this site is HTTPS-only. Without it, the first request of every visit can be downgraded or intercepted before the redirect to HTTPS happens.',
  attack:
    'An attacker on the same network answers the initial http:// request with their own page before the HTTPS redirect, stealing credentials or injecting script into what looks like the real site (SSL stripping).',
  tags: ['headers', 'transport'],
  appliesTo: 'document',
  remediation: headerRemediation({
    header: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload',
    expressCode: `app.use((req, res, next) => {
  if (req.secure) {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }
  next();
});`,
    nextjsCode: `const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
        ],
      },
    ];
  },
};
export default nextConfig;`,
    nginxCode: `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`,
  }),
  evaluate(ctx) {
    const isHttps = ctx.event.url.startsWith('https://');
    if (!isHttps) return [];
    if (hasHeader(ctx.event.responseHeaders, 'strict-transport-security')) return [];
    return [
      {
        key: 'hsts',
        message: 'This HTTPS response has no Strict-Transport-Security header.',
        detail: 'Browsers will keep allowing http:// for this host until they see HSTS.',
      },
    ];
  },
};

export default rule;
