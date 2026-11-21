import { isLocalHost } from '../../core/url';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'mixed-content',
  severity: 'high',
  title: 'Mixed content: HTTPS page loads an HTTP resource',
  what: 'An HTTPS page requested a subresource over plain HTTP, so that part of the page travels unencrypted.',
  why: 'The HTTPS padlock describes the connection to the page’s origin, not to every resource. An HTTP script or iframe can be modified in transit, and a modified script runs with full access to the HTTPS page.',
  attack:
    'On a shared network, the attacker intercepts the plain-HTTP script request and returns malicious JavaScript. The payload runs inside the secure page, reads tokens and calls authenticated APIs.',
  tags: ['transport', 'mixed-content'],
  appliesTo: 'request',
  remediation: remediation(
    `// Express: upgrade insecure subresource URLs and redirect HTTP to HTTPS
app.use((req, res, next) => {
  if (!req.secure) return res.redirect(308, \`https://\${req.headers.host}\${req.originalUrl}\`);
  next();
});

// Serve assets with protocol-relative or absolute HTTPS URLs, never http://.`,
    `// next.config.mjs: enforce HTTPS + HSTS
const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [{ key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' }],
      },
    ];
  },
};
export default nextConfig;`,
    `# nginx: redirect all plain HTTP to HTTPS
server {
  listen 80;
  server_name example.com;
  return 308 https://$host$request_uri;
}`,
  ),
  evaluate(ctx) {
    if (!ctx.event.pageOrigin.startsWith('https://')) return [];
    if (!ctx.event.url.startsWith('http://')) return [];
    if (ctx.event.resourceType === 'document') return [];
    const host = (() => {
      try {
        return new URL(ctx.event.url).hostname;
      } catch {
        return '';
      }
    })();
    if (isLocalHost(host)) return [];
    return [
      {
        key: `mixed:${host}`,
        message: `HTTPS page loaded ${ctx.event.url} over HTTP.`,
        detail:
          ctx.event.resourceType === 'script'
            ? 'An HTTP script can be modified in transit and then runs with full access to the secure page.'
            : 'Anything on this plain-HTTP connection can be read or modified by the network.',
      },
    ];
  },
};

export default rule;
