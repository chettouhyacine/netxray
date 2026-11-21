import { tokenKey, maskToken } from '../lib/jwts';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const MAX_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

const rule: Rule = {
  id: 'jwt-long-expiry',
  severity: 'low',
  title: 'JWT lives longer than 30 days',
  what: 'A JWT’s `exp` claim is more than 30 days after it was issued (or after now, when `iat` is missing).',
  why: 'Long-lived access tokens cannot be revoked without server-side state, so a leaked token grants access for weeks or months. Short access tokens plus refresh tokens limit the blast radius.',
  attack:
    'The attacker steals one access token and uses it for a month, even after the victim changes their password, because there is no revocation path for a stateless token.',
  tags: ['jwt', 'auth'],
  appliesTo: 'response',
  remediation: remediation(
    `// Express: 15-minute access token, 30-day rotating refresh token
const accessToken = jwt.sign({ sub: user.id }, process.env.JWT_SECRET!, {
  expiresIn: '15m',
});

const refreshToken = jwt.sign({ sub: user.id, jti: randomUUID() }, process.env.REFRESH_SECRET!, {
  expiresIn: '30d',
});`,
    `// NextAuth: keep sessions short and refresh server-side
export const authOptions = {
  session: { strategy: 'jwt', maxAge: 60 * 60 }, // 1 hour
};`,
    `# nginx: reject obviously stale bearer tokens at the edge
auth_jwt_require $jwt_valid;`,
  ),
  evaluate(ctx) {
    const now = Date.now();
    return ctx.jwts
      .filter((jwt) => jwt.expiresAt !== null)
      .filter((jwt) => {
        const start = jwt.issuedAt ?? now;
        return (jwt.expiresAt ?? 0) - start > MAX_LIFETIME_MS;
      })
      .map((jwt) => {
        const days = Math.round(((jwt.expiresAt ?? 0) - (jwt.issuedAt ?? now)) / (24 * 60 * 60 * 1000));
        return {
          key: `long-exp:${tokenKey(jwt.raw)}`,
          message: `JWT is valid for about ${days} days.`,
          detail: 'Prefer 5–15 minute access tokens with refresh and revocation.',
          evidence: maskToken(jwt.raw),
        };
      });
  },
};

export default rule;
