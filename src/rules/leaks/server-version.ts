import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const DISCLOSURE_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-runtime'];

const rule: Rule = {
  id: 'server-version-disclosure',
  severity: 'low',
  title: 'Server technology and version disclosed',
  what: 'A response advertises the server software or framework, often with an exact version.',
  why: 'Version banners turn a broad scan into a targeted attack. Knowing "Express 4.16.3" or "nginx/1.18.0" lets an attacker jump straight to known CVEs for that exact release.',
  attack:
    'An automated scanner reads X-Powered-By, matches the version against public CVE databases, and launches the matching exploit instead of blind fuzzing.',
  tags: ['leaks', 'fingerprinting'],
  appliesTo: 'response',
  remediation: remediation(
    `// Express: hide the framework banner
app.disable('x-powered-by');

app.use((req, res, next) => {
  res.removeHeader('X-AspNet-Version');
  res.removeHeader('X-Runtime');
  next();
});`,
    `// next.config.mjs
const nextConfig = {
  poweredByHeader: false,
};
export default nextConfig;`,
    `# nginx: suppress version in headers and error pages
server_tokens off;
more_clear_headers Server;   # requires headers-more module`,
  ),
  evaluate(ctx) {
    return DISCLOSURE_HEADERS.flatMap((name) => {
      const value = ctx.event.responseHeaders[name];
      if (!value) return [];
      return [
        {
          key: name,
          message: `Response advertises \`${name}: ${value}\`.`,
          detail: 'Remove or genericise version banners; keep the real version in server-side logs.',
          evidence: `${name}: ${value}`,
        },
      ];
    });
  },
};

export default rule;
