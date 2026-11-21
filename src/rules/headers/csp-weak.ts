import { headerRemediation } from '../lib/remediation';
import type { Rule } from '../types';

const WEAK_TOKENS = ["'unsafe-inline'", "'unsafe-eval'", 'data:', '*'];

const rule: Rule = {
  id: 'header-csp-weak',
  severity: 'medium',
  title: 'Content-Security-Policy has weak directives',
  what: 'The CSP exists but allows inline scripts, eval, data: URLs or a wildcard origin.',
  why: "A CSP containing 'unsafe-inline' or 'unsafe-eval' does not stop the most common XSS payloads. It looks like protection in a security scanner while giving the page almost no real defence.",
  attack:
    'The attacker injects <script>alert(document.cookie)</script> or an onerror handler. Because inline execution is allowed, the CSP never blocks it, and the payload steals the session.',
  tags: ['headers', 'xss'],
  appliesTo: 'document',
  remediation: headerRemediation({
    header: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self' 'nonce-abc123'; object-src 'none'",
    expressCode: `// Move inline handlers into files, then drop 'unsafe-inline'.
// A per-response nonce is safer than a hash for dynamic pages.
app.use((req, res, next) => {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.cspNonce = nonce;
  res.setHeader(
    'Content-Security-Policy',
    \`default-src 'self'; script-src 'self' 'nonce-\${nonce}'; object-src 'none'\`,
  );
  next();
});`,
    nextjsCode: `// Next.js middleware: nonce per request, then read it in your layout
import { NextResponse } from 'next/server';

export function middleware(request: Request) {
  const nonce = crypto.randomUUID().replace(/-/g, '');
  const response = NextResponse.next();
  response.headers.set(
    'Content-Security-Policy',
    \`default-src 'self'; script-src 'self' 'nonce-\${nonce}'; object-src 'none'\`,
  );
  return response;
}`,
    nginxCode: `# Remove unsafe-inline/unsafe-eval and list explicit script origins
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.example.com; object-src 'none'" always;`,
  }),
  evaluate(ctx) {
    const csp = ctx.event.responseHeaders['content-security-policy'];
    if (!csp) return [];
    const directives = csp
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean);
    const scriptDirective =
      directives.find((d) => d.toLowerCase().startsWith('script-src')) ??
      directives.find((d) => d.toLowerCase().startsWith('default-src')) ??
      '';
    const lowered = scriptDirective.toLowerCase();
    const weak = WEAK_TOKENS.filter((token) => lowered.includes(token));
    if (weak.length === 0) return [];
    return [
      {
        key: `directive:${weak.join(',')}`,
        message: `CSP allows ${weak.join(', ')} in ${scriptDirective.split(/\s+/)[0] ?? 'script-src'}.`,
        detail: 'These tokens make the policy ineffective against common injection payloads.',
        evidence: csp,
      },
    ];
  },
};

export default rule;
