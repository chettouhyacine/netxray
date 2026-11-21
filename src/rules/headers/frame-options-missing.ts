import { headerRemediation } from '../lib/remediation';
import type { Rule } from '../types';

/**
 * Reads only the `frame-ancestors` directive. A value of `*`, an empty
 * directive or a bare scheme source (`https:`) allows arbitrary framing and
 * must not be mistaken for protection.
 */
function hasProtectiveFrameAncestors(csp: string): boolean {
  const directive = csp
    .split(';')
    .map((part) => part.trim())
    .find((part) => /^frame-ancestors\b/i.test(part));
  if (!directive) return false;
  const sources = directive
    .replace(/^frame-ancestors\s*/i, '')
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
  if (sources.length === 0) return false;
  return !sources.some((source) => source === '*' || /^[a-z][a-z0-9+.-]*:$/.test(source));
}

const rule: Rule = {
  id: 'header-frame-options-missing',
  severity: 'medium',
  title: 'Page can be framed by other sites',
  what: 'The response has neither X-Frame-Options nor a CSP frame-ancestors directive, so any site can embed this page in an iframe.',
  why: 'Framing enables clickjacking: the attacker loads your real, logged-in page invisibly under their own UI so that clicks land on your buttons (delete account, transfer funds, change email).',
  attack:
    'The victim visits a free-movie page showing a fake "Play" button. Under it sits your account page; the click actually confirms a password change to the attacker’s address.',
  tags: ['headers', 'clickjacking'],
  appliesTo: 'document',
  remediation: headerRemediation({
    header: 'X-Frame-Options',
    value: 'DENY',
    expressCode: `// X-Frame-Options is the simple version; CSP frame-ancestors is the modern one.
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
  next();
});`,
    nginxCode: `add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "frame-ancestors 'none'" always;`,
  }),
  evaluate(ctx) {
    const headers = ctx.event.responseHeaders;
    const xfo = (headers['x-frame-options'] ?? '').trim().toLowerCase();
    const xfoProtects = xfo === 'deny' || xfo === 'sameorigin';
    if (xfoProtects) return [];
    const csp = headers['content-security-policy'] ?? '';
    if (hasProtectiveFrameAncestors(csp)) return [];
    const hasWeakControl = Boolean(xfo) || /frame-ancestors/i.test(csp);
    return [
      {
        key: 'framing',
        message: 'No effective X-Frame-Options or frame-ancestors directive.',
        detail: hasWeakControl
          ? 'The response mentions framing protection, but the value still allows arbitrary origins.'
          : 'The browser will let any origin frame this document.',
      },
    ];
  },
};

export default rule;
