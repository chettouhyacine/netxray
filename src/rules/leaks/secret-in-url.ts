import { isJwt } from '../../core/jwt';
import { isSensitiveName, maskSecret } from '../../core/redact';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const PLACEHOLDERS = new Set(['', 'null', 'undefined', 'true', 'false', '0', '1', 'test', 'example', 'changeme']);

const rule: Rule = {
  id: 'secret-in-url',
  severity: 'high',
  title: 'Secret in URL query string',
  what: 'A credential-looking value (token, API key, password or JWT) appears in the URL query string.',
  why: 'URLs are stored everywhere outside your application: browser history, proxy and server logs, analytics, Referer headers sent to third parties, and screenshots in bug reports. A secret in a URL is effectively published.',
  attack:
    'An attacker reads a leaked URL from a shared screenshot, an analytics dashboard or a Referer header captured by a third-party script, then replays the token against your API.',
  tags: ['leaks', 'secrets'],
  appliesTo: 'request',
  remediation: remediation(
    `// Express: accept credentials in headers, never in the query
app.post('/api/action', requireAuth, (req, res) => {
  // Authorization: Bearer <token>
  res.json({ ok: true });
});

// If you must support legacy links, exchange the token once, then redirect
// to a URL with the token removed.`,
    `// Next.js: read the Authorization header in a Route Handler
export async function POST(request: Request) {
  const token = request.headers.get('authorization')?.replace(/^Bearer /, '');
  if (!token) return new Response('Unauthorized', { status: 401 });
  // ...
}`,
    `# nginx: keep query strings out of access logs for sensitive routes
map $request_uri $loggable_uri {
  default $request_uri;
  "~^(/api/reset)" $1;
}
log_format safe '$remote_addr - $loggable_uri';`,
  ),
  evaluate(ctx) {
    const hits: { key: string; message: string; detail: string; evidence: string }[] = [];
    for (const [name, values] of Object.entries(ctx.event.query)) {
      for (const value of values) {
        const sensitiveName = isSensitiveName(name);
        const jwt = isJwt(value);
        if (!jwt && (!sensitiveName || value.trim().length < 8 || PLACEHOLDERS.has(value.toLowerCase()))) {
          continue;
        }
        hits.push({
          key: `query:${name}`,
          message: jwt ? `A JWT is passed in the \`${name}\` query parameter.` : `Query parameter \`${name}\` carries a secret-looking value.`,
          detail: 'URLs are logged, cached and forwarded in Referer headers; move credentials into the Authorization header or a request body.',
          evidence: maskSecret(value),
        });
      }
    }
    return hits;
  },
};

export default rule;
