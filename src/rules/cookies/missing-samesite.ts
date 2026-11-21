import { maskSecret } from '../../core/redact';
import { cookieFacts } from '../lib/cookies';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'cookie-missing-samesite',
  severity: 'medium',
  title: 'Cookie has no explicit SameSite protection',
  what: 'A cookie is set without a SameSite attribute, or with SameSite=None without Secure, so other sites can trigger requests that carry it.',
  why: 'SameSite tells the browser whether to attach the cookie when a request starts from another site. Without it, cross-site form posts and image requests carry your session and can perform actions as the user (CSRF).',
  attack:
    'The attacker hosts a form that POSTs to https://your-app.example/account/email with their address. A logged-in visitor loads the page, the browser sends the session cookie, and the victim’s account email is changed silently.',
  tags: ['cookies', 'csrf'],
  appliesTo: 'document',
  remediation: remediation(
    `res.cookie('sid', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',   // or 'strict' for sensitive actions
});`,
    `jar.set('sid', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/',
});`,
    `proxy_cookie_flags ~* \\bsid\\b samesite=lax httponly secure;`,
  ),
  evaluate(ctx) {
    return cookieFacts(ctx)
      .filter((cookie) => cookie.sameSite === 'unspecified' || (cookie.sameSite === 'none' && !cookie.secure))
      .map((cookie) => ({
        key: `${cookie.name}@${cookie.domain}`,
        message:
          cookie.sameSite === 'none'
            ? `Cookie \`${cookie.name}\` uses SameSite=None without Secure.`
            : `Cookie \`${cookie.name}\` has no SameSite attribute.`,
        detail:
          cookie.sameSite === 'none'
            ? 'Chrome rejects SameSite=None cookies that are not also Secure, and other browsers send them on cross-site requests.'
            : 'Browsers default this to Lax, but the protection is implicit and older clients may ignore it.',
        evidence: maskSecret(cookie.value),
      }));
  },
};

export default rule;
