import { cacheControlDirectives } from '../../core/headers';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'cache-sensitive-response',
  severity: 'medium',
  title: 'Sensitive response may be cached',
  what: 'A response that sets cookies or was requested with an Authorization header is cacheable (public or max-age without private/no-store).',
  why: 'Shared caches (CDNs, corporate proxies) and browser caches can store the response and serve it to another user or after logout. Cache keys are URLs, not users.',
  attack:
    'The attacker requests the same URL from a shared proxy after the victim did and receives the cached personalized response, including account data or tokens.',
  tags: ['caching', 'leaks'],
  appliesTo: 'response',
  remediation: remediation(
    `// Express: personalized responses must not be stored
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'private, no-store');
  next();
});`,
    `// Next.js Route Handler
export const dynamic = 'force-dynamic';

return Response.json(data, {
  headers: { 'Cache-Control': 'private, no-store' },
});`,
    `# nginx
add_header Cache-Control "private, no-store" always;
proxy_no_cache $http_authorization;`,
  ),
  evaluate(ctx) {
    const sensitive = ctx.event.setCookie.length > 0 || Boolean(ctx.event.requestHeaders.authorization);
    if (!sensitive) return [];
    const directives = cacheControlDirectives(ctx.event.cacheControl);
    if (directives.length === 0) return [];
    if (directives.includes('no-store') || directives.includes('private')) return [];
    const maxAge = directives.find((directive) => directive.startsWith('max-age='));
    const publicCache = directives.includes('public') || Boolean(maxAge);
    if (!publicCache) return [];
    return [
      {
        key: `cache:${ctx.event.url}`,
        message: `Sensitive response is cacheable${maxAge ? ` (${maxAge})` : ' (public)'}.`,
        detail: 'Add Cache-Control: private, no-store to personalized responses.',
        evidence: ctx.event.cacheControl,
      },
    ];
  },
};

export default rule;
