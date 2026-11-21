import { isLocalHost, hostOf } from '../../core/url';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'insecure-http',
  severity: 'medium',
  title: 'Page is served over plain HTTP',
  what: 'The main document was loaded over http:// instead of https://.',
  why: 'Without TLS, every byte (HTML, cookies, login forms, API responses) travels in clear text and can be read or modified by anyone on the network. Browsers also disable powerful APIs on insecure origins.',
  attack:
    'A café Wi-Fi attacker rewrites the HTTP page in transit, injects a fake login form that posts credentials to their server, or steals the session cookie from the unencrypted request headers.',
  tags: ['transport', 'tls'],
  appliesTo: 'document',
  remediation: remediation(
    `// Express behind a proxy: force HTTPS, trust X-Forwarded-Proto
app.set('trust proxy', 1);

app.use((req, res, next) => {
  if (req.secure) return next();
  res.redirect(308, \`https://\${req.headers.host}\${req.originalUrl}\`);
});`,
    `// Next.js middleware: redirect HTTP to HTTPS in production
import { NextResponse } from 'next/server';

export function middleware(request: Request) {
  const url = new URL(request.url);
  if (url.protocol === 'http:' && process.env.NODE_ENV === 'production') {
    url.protocol = 'https:';
    return NextResponse.redirect(url, 308);
  }
  return NextResponse.next();
}`,
    `# nginx: HTTP -> HTTPS
server {
  listen 80;
  server_name example.com;
  return 308 https://$host$request_uri;
}`,
  ),
  evaluate(ctx) {
    if (ctx.event.resourceType !== 'document') return [];
    if (!ctx.event.url.startsWith('http://')) return [];
    if (isLocalHost(hostOf(ctx.event.url))) return [];
    return [
      {
        key: 'document-http',
        message: 'The main document is served over plain HTTP.',
        detail: 'Everything on this page can be read or modified in transit.',
      },
    ];
  },
};

export default rule;
