import { sensitiveClaims } from '../../core/jwt';
import { tokenKey, maskToken } from '../lib/jwts';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'jwt-sensitive-payload',
  severity: 'high',
  title: 'Sensitive data inside a JWT payload',
  what: 'A JWT payload contains claims such as passwords, card numbers, API keys or private keys.',
  why: 'JWT payloads are base64url, not encryption. Anyone who sees the token can read every claim, and tokens are routinely stored in localStorage, logs, URLs and analytics. Secrets inside them are public.',
  attack:
    'An attacker with read access to the token (XSS, a HAR file, a proxy log, a screenshot) decodes the payload and obtains the embedded password, API key or personal data directly.',
  tags: ['jwt', 'leaks'],
  appliesTo: 'response',
  remediation: remediation(
    `// Express: keep claims minimal and non-sensitive
const token = jwt.sign(
  { sub: user.id },                 // identifier only
  process.env.JWT_SECRET!,
  { expiresIn: '15m' },
);

// Look up profiles and permissions server-side on each request.`,
    `// jose: identifier-only claims
const token = await new SignJWT({ sub: user.id })
  .setProtectedHeader({ alg: 'HS256' })
  .setExpirationTime('15m')
  .sign(secret);`,
    `# nginx: log only token presence, never the token itself
log_format no_token '$remote_addr "$request_method $uri"';
access_log /var/log/nginx/access.log no_token;`,
  ),
  evaluate(ctx) {
    return ctx.jwts.flatMap((jwt) => {
      const claims = sensitiveClaims(jwt.payload);
      if (claims.length === 0) return [];
      return [
        {
          key: `claims:${claims.join(',')}:${tokenKey(jwt.raw)}`,
          message: `JWT payload contains sensitive claim(s): ${claims.join(', ')}.`,
          detail: 'Payloads are only encoded, never encrypted. Remove these claims and fetch data server-side.',
          evidence: maskToken(jwt.raw),
        },
      ];
    });
  },
};

export default rule;
