import { maskSecret } from '../../core/redact';
import { cookieFacts, looksLikeSessionCookie } from '../lib/cookies';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'cookie-session-js-readable',
  severity: 'high',
  title: 'Session cookie is readable by JavaScript',
  what: 'A cookie whose name suggests it holds a session or auth token is missing HttpOnly, so page scripts can read and exfiltrate it.',
  why: 'This is the highest-value cookie on the site. If it is script-readable, a single XSS or a malicious third-party script can take over accounts at scale without ever guessing a password.',
  attack:
    'A compromised npm package or third-party tag reads document.cookie, base64-encodes it and sends it in an image request to an attacker domain. The attacker sets the cookie in their own browser and is logged in as the victim.',
  tags: ['cookies', 'session', 'critical'],
  appliesTo: 'document',
  remediation: remediation(
    `// Express: mark the session cookie HttpOnly (express-session does this by default)
app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET!,
  cookie: { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 3600_000 },
}));`,
    `// NextAuth (Auth.js) session cookie is HttpOnly by default. If you set it
// yourself, never expose the raw session id to client JavaScript:
jar.set('__Host-sid', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/',
});`,
    `# Prefer application-level cookies; if you must patch upstream:
proxy_cookie_flags ~* \\b(sid|session|auth|token)\\b httponly secure;`,
  ),
  evaluate(ctx) {
    return cookieFacts(ctx)
      .filter((cookie) => !cookie.httpOnly && looksLikeSessionCookie(cookie.name))
      .map((cookie) => ({
        key: `${cookie.name}@${cookie.domain}`,
        message: `Session cookie \`${cookie.name}\` is script-readable.`,
        detail: `Any JavaScript on this page can call document.cookie and steal this session. Domain=${cookie.domain}.`,
        evidence: maskSecret(cookie.value),
      }));
  },
};

export default rule;
