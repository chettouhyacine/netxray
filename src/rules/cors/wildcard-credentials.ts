import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'cors-wildcard-credentials',
  severity: 'high',
  title: 'CORS allows any origin with credentials',
  what: 'The response sends Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.',
  why: 'This combination is a configuration bug: it tells the browser any website may read credentialed responses. Browsers reject the wildcard when credentials are used, so the app is either broken or reaching for "reflect any origin", which is worse.',
  attack:
    'A malicious site sends a fetch to your API with credentials: "include". If the server reflects the origin instead of using *, it can read the victim’s private data (profile, invoices, API keys) directly in the browser.',
  tags: ['cors', 'api'],
  appliesTo: 'response',
  remediation: remediation(
    `// Express: allow-list known origins, never * with credentials
const allowed = new Set(['https://app.example.com']);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowed.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});`,
    `// Next.js Route Handler: echo only allow-listed origins
const allowed = new Set(['https://app.example.com']);

export async function OPTIONS(request: Request) {
  const origin = request.headers.get('origin') ?? '';
  const headers = new Headers({ Vary: 'Origin' });
  if (allowed.has(origin)) {
    headers.set('Access-Control-Allow-Origin', origin);
    headers.set('Access-Control-Allow-Credentials', 'true');
  }
  return new Response(null, { status: 204, headers });
}`,
    `# nginx: use a map instead of a literal *
map $http_origin $cors_origin {
  default "";
  "https://app.example.com" $http_origin;
}
add_header Access-Control-Allow-Origin $cors_origin always;
add_header Access-Control-Allow-Credentials "true" always;
add_header Vary "Origin" always;`,
  ),
  evaluate(ctx) {
    const headers = ctx.event.responseHeaders;
    const origin = headers['access-control-allow-origin'];
    const credentials = headers['access-control-allow-credentials'];
    if (origin?.trim() === '*' && credentials?.toLowerCase() === 'true') {
      return [
        {
          key: 'wildcard-credentials',
          message: 'Access-Control-Allow-Origin: * combined with Allow-Credentials: true.',
          detail: 'Browsers refuse this combination, so either credentialed CORS silently fails or the server falls back to reflecting origins.',
          evidence: `Access-Control-Allow-Origin: ${origin}`,
        },
      ];
    }
    return [];
  },
};

export default rule;
