import { hostOf } from '../../core/url';
import { cookieFacts } from '../lib/cookies';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'cookie-broad-scope',
  severity: 'low',
  title: 'Cookie is shared across subdomains',
  what: 'A cookie sets an explicit Domain attribute that covers every subdomain of the site, which is broader than the page that set it.',
  why: 'Every subdomain can read and overwrite a cookie shared this way. A staging server, an old marketing site or a user-content subdomain becomes an entry point into the main session.',
  attack:
    'An attacker takes over a neglected subdomain (or gets a page on user-content.example.com). Because the session cookie is scoped to .example.com, their JavaScript reads it and takes over the main application.',
  tags: ['cookies', 'scope'],
  appliesTo: 'document',
  remediation: remediation(
    `// Prefer host-only cookies: do not pass a Domain attribute.
res.cookie('sid', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/',
  // domain: omitted on purpose -> host-only
});`,
    `jar.set('sid', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/',
  // no domain: cookie stays on this exact host
});`,
    `# Domain is decided by the app. If an upstream sets it too broadly:
proxy_cookie_path / "/; secure; HttpOnly; SameSite=Lax";`,
  ),
  evaluate(ctx) {
    const host = hostOf(ctx.event.url);
    return cookieFacts(ctx)
      .filter((cookie) => {
        if (cookie.hostOnly) return false;
        const scope = cookie.domain.replace(/^\./, '').toLowerCase();
        // Only flag when the scope is strictly wider than the response host.
        return Boolean(host) && scope !== host && host.endsWith(`.${scope}`);
      })
      .map((cookie) => ({
        key: `${cookie.name}@${cookie.domain}`,
        message: `Cookie \`${cookie.name}\` is shared with *.${cookie.domain.replace(/^\./, '')}.`,
        detail: `The response host is ${host}. A domain-wide cookie is readable by every subdomain, including forgotten ones.`,
      }));
  },
};

export default rule;
