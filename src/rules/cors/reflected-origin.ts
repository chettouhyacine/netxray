import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'cors-reflected-origin',
  severity: 'high',
  title: 'CORS reflects arbitrary origins',
  what: 'The API echoes whatever Origin the caller sent back in Access-Control-Allow-Origin, instead of checking it against an allow-list.',
  why: 'Reflecting the Origin means every website becomes an allowed origin. Combined with cookies, any page a logged-in user visits can read their private API data. It also defeats the point of CORS entirely.',
  attack:
    'The victim visits attacker.example, which runs fetch("https://api.example.com/me", {credentials:"include"}). The API answers with the attacker’s Origin echoed back, so the browser lets the attacker’s script read the victim’s account data.',
  tags: ['cors', 'api'],
  appliesTo: 'response',
  remediation: remediation(
    `// Express: compare against an allow-list, never echo blindly
const allowed = new Set(['https://app.example.com']);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowed.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  next();
});`,
    `// Next.js middleware
import { NextResponse } from 'next/server';

const allowed = new Set(['https://app.example.com']);

export function middleware(request: Request) {
  const origin = request.headers.get('origin');
  const response = NextResponse.next();
  if (origin && allowed.has(origin)) {
    response.headers.set('Access-Control-Allow-Origin', origin);
    response.headers.set('Vary', 'Origin');
  }
  return response;
}`,
    `# nginx: explicit allow-list, no $http_origin pass-through
map $http_origin $cors_origin {
  default "";
  "~^https://(app|admin)\\.example\\.com$" $http_origin;
}
add_header Access-Control-Allow-Origin $cors_origin always;`,
  ),
  evaluate(ctx) {
    const headers = ctx.event.responseHeaders;
    const origin = headers['access-control-allow-origin']?.trim();
    const requestOrigin = ctx.event.requestHeaders.origin?.trim();
    if (!origin || !requestOrigin || origin === '*') return [];
    if (origin !== requestOrigin) return [];
    // Echoing the page's own origin is normal; echoing anything else is not.
    if (origin === ctx.event.pageOrigin) return [];
    const credentials = headers['access-control-allow-credentials']?.toLowerCase() === 'true';
    return [
      {
        key: `reflected:${origin}`,
        message: `The server echoed Origin ${origin} back to the caller.`,
        detail: credentials
          ? 'Credentials are also allowed, so this origin can read authenticated responses.'
          : 'The allow-list is not enforced; any origin that asks gets access.',
        evidence: `Access-Control-Allow-Origin: ${origin}`,
      },
    ];
  },
};

export default rule;
