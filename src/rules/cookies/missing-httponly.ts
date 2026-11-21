import { maskSecret } from '../../core/redact';
import { cookieFacts } from '../lib/cookies';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'cookie-missing-httponly',
  severity: 'medium',
  title: 'Cookie can be read by JavaScript',
  what: 'A cookie is set without the HttpOnly attribute, so any script on the page can read it with document.cookie.',
  why: 'Session cookies and other sensitive values should be invisible to JavaScript. If they are readable, one cross-site scripting (XSS) bug is enough to steal a logged-in session.',
  attack:
    'An attacker who lands an XSS payload (through a comment field, a compromised dependency or an injected analytics script) runs document.cookie and sends the stolen cookie to their own server, then reuses it to impersonate the user.',
  tags: ['cookies', 'session'],
  appliesTo: 'document',
  remediation: remediation(
    `// Express: set HttpOnly on every sensitive cookie
res.cookie('sid', sessionId, {
  httpOnly: true,   // blocks document.cookie access
  secure: true,     // HTTPS only
  sameSite: 'lax',
});`,
    `// Next.js Route Handler
import { cookies } from 'next/headers';

const jar = await cookies();
jar.set('sid', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/',
});`,
    `# nginx cannot add HttpOnly to an upstream Set-Cookie.
# Set it in the application, or rewrite explicitly:
proxy_cookie_flags ~* \\bsid\\b httponly secure samesite=lax;`,
  ),
  evaluate(ctx) {
    return cookieFacts(ctx)
      .filter((cookie) => !cookie.httpOnly)
      .map((cookie) => ({
        key: `${cookie.name}@${cookie.domain}`,
        message: `Cookie \`${cookie.name}\` has no HttpOnly flag.`,
        detail: `Scope: domain=${cookie.domain}, path=${cookie.path}. JavaScript can read this cookie.`,
        evidence: maskSecret(cookie.value),
      }));
  },
};

export default rule;
