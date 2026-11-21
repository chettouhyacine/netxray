import { maskSecret } from '../../core/redact';
import { cookieFacts, looksLikeSessionCookie, pageIsSecure } from '../lib/cookies';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'cookie-missing-secure',
  severity: 'medium',
  title: 'Cookie can travel over plain HTTP',
  what: 'A cookie on an HTTPS page is set without the Secure attribute, so the browser may also send it over an unencrypted connection.',
  why: 'Secure tells the browser to attach the cookie only to HTTPS requests. Without it, a single http:// request to the same host leaks the cookie on the wire where anyone on the network can read it.',
  attack:
    'On public Wi-Fi, an attacker injects a plain-HTTP request to your domain (for example a downgraded image). The browser attaches the cookie, and the attacker captures the session from the unencrypted traffic.',
  tags: ['cookies', 'transport'],
  appliesTo: 'document',
  remediation: remediation(
    `res.cookie('theme', 'dark', {
  secure: true,     // HTTPS only
  httpOnly: true,
  sameSite: 'lax',
});`,
    `jar.set('theme', 'dark', {
  secure: true,
  httpOnly: true,
  sameSite: 'lax',
  path: '/',
});`,
    `proxy_cookie_flags ~* \\btheme\\b secure httponly;`,
  ),
  evaluate(ctx) {
    if (!pageIsSecure(ctx)) return [];
    return cookieFacts(ctx)
      // Preference cookies missing Secure are low-value noise; the attack this
      // rule claims is session theft, so only session-like names are reported.
      .filter((cookie) => !cookie.secure && looksLikeSessionCookie(cookie.name))
      .map((cookie) => ({
        key: `${cookie.name}@${cookie.domain}`,
        message: `Cookie \`${cookie.name}\` has no Secure flag.`,
        detail: 'This cookie can be sent over http:// where it is readable by network attackers.',
        evidence: maskSecret(cookie.value),
      }));
  },
};

export default rule;
