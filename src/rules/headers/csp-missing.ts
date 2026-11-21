import { hasHeader } from '../../core/headers';
import { headerRemediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'header-csp-missing',
  severity: 'high',
  title: 'No Content-Security-Policy',
  what: 'The page is served without a Content-Security-Policy (CSP) header, so the browser has no allow-list for scripts, styles, frames and connections.',
  why: 'CSP is the seatbelt for the browser: it makes many XSS payloads fail because injected inline scripts and unknown origins are blocked. Without it, any script injection runs with full access to the page, its cookies and its API calls.',
  attack:
    'An attacker injects a script through a vulnerable input or a compromised dependency. With no CSP, the browser executes it, reads localStorage tokens and posts them to an attacker-controlled domain.',
  tags: ['headers', 'xss'],
  appliesTo: 'document',
  remediation: headerRemediation({
    header: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    expressCode: `// Express: start strict, then widen only where needed
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  );
  next();
});`,
    nextjsCode: `// next.config.mjs: nonces are strongly preferred over 'unsafe-inline'
const csp = [
  "default-src 'self'",
  "script-src 'self' 'nonce-<generated-per-request>'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join('; ');

const nextConfig = {
  async headers() {
    return [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: csp }] }];
  },
};
export default nextConfig;`,
    nginxCode: `# nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;`,
  }),
  evaluate(ctx) {
    if (hasHeader(ctx.event.responseHeaders, 'content-security-policy')) return [];
    return [
      {
        key: 'csp',
        message: 'The document response has no Content-Security-Policy header.',
        detail: 'Any injected inline script will run unopposed.',
      },
    ];
  },
};

export default rule;
