import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const DANGEROUS_METHODS = new Set(['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']);

const rule: Rule = {
  id: 'cors-permissive',
  severity: 'medium',
  title: 'CORS allows more methods and headers than needed',
  what: 'Access-Control-Allow-Methods lists destructive verbs (PUT/DELETE/PATCH), or Access-Control-Allow-Headers is a wildcard or includes sensitive headers.',
  why: 'CORS is an allow-list, not a convenience toggle. Listing every method and header broadens what a browser can be tricked into sending, and a wildcard header list can expose internal headers such as Authorization.',
  attack:
    'A malicious origin sends a credentialed DELETE or a request with custom internal headers (X-Admin, X-Impersonate) that the API trusts. The permissive preflight says yes to everything.',
  tags: ['cors', 'api'],
  appliesTo: 'response',
  remediation: remediation(
    `// Express: answer preflight with the minimum the app needs
res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
res.setHeader('Access-Control-Max-Age', '600');`,
    `// Next.js Route Handler preflight
return new Response(null, {
  status: 204,
  headers: {
    'Access-Control-Allow-Methods': 'GET, POST',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  },
});`,
    `# nginx: only the methods and headers you actually serve
add_header Access-Control-Allow-Methods "GET, POST" always;
add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;`,
  ),
  evaluate(ctx) {
    const headers = ctx.event.responseHeaders;
    const origin = headers['access-control-allow-origin'];
    if (!origin) return [];
    const methods = (headers['access-control-allow-methods'] ?? '')
      .split(',')
      .map((method) => method.trim().toUpperCase())
      .filter(Boolean);
    const allowHeaders = (headers['access-control-allow-headers'] ?? '').toLowerCase();
    const hits = [];
    const dangerous = methods.filter((method) => DANGEROUS_METHODS.has(method));
    if (dangerous.length > 0) {
      hits.push({
        key: `methods:${dangerous.join(',')}`,
        message: `CORS allows ${dangerous.join(', ')}.`,
        detail: 'Only list methods that this endpoint genuinely needs.',
      });
    }
    if (allowHeaders.trim() === '*' || allowHeaders.includes('authorization') === false && allowHeaders.includes('x-')) {
      // A wildcard is the clear case; custom X-* headers are worth a mention.
      hits.push({
        key: 'headers',
        message: allowHeaders.trim() === '*' ? 'CORS allows every request header (*).' : 'CORS allows custom X-* headers.',
        detail: 'Wildcards make internal headers reachable from any allowed origin.',
      });
    }
    return hits;
  },
};

export default rule;
