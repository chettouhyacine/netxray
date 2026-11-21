import { tokenKey, maskToken } from '../lib/jwts';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'jwt-missing-exp',
  severity: 'medium',
  title: 'JWT has no expiry',
  what: 'A JWT has no `exp` claim, so it never expires on its own.',
  why: 'A token without expiry is a permanent password. If it leaks (through logs, a stolen laptop, a screenshot or an XSS bug), it stays valid until you rotate the signing key and invalidate every session.',
  attack:
    'The attacker steals a token once from an old HAR file or a compromised browser extension and keeps using it indefinitely, long after the user has logged out.',
  tags: ['jwt', 'auth'],
  appliesTo: 'response',
  remediation: remediation(
    `// jsonwebtoken: short-lived access token + refresh token
const accessToken = jwt.sign(
  { sub: user.id, role: user.role },
  process.env.JWT_SECRET!,
  { algorithm: 'HS256', expiresIn: '15m', issuer: 'https://app.example.com' },
);`,
    `// jose: setExpirationTime is explicit
const accessToken = await new SignJWT({ sub: user.id, role: user.role })
  .setProtectedHeader({ alg: 'HS256' })
  .setIssuer('https://app.example.com')
  .setExpirationTime('15m')
  .sign(secret);`,
    `# nginx: cap upstream token lifetimes at the gateway when possible
proxy_set_header X-Max-Token-Age "900";`,
  ),
  evaluate(ctx) {
    return ctx.jwts
      .filter((jwt) => jwt.payload && jwt.expiresAt === null)
      .map((jwt) => ({
        key: `no-exp:${tokenKey(jwt.raw)}`,
        message: 'A JWT has no `exp` claim.',
        detail: 'Give access tokens a short lifetime (minutes, not months) and rotate them.',
        evidence: maskToken(jwt.raw),
      }));
  },
};

export default rule;
