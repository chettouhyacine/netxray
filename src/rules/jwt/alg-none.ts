import { tokenKey, maskToken } from '../lib/jwts';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'jwt-alg-none',
  severity: 'high',
  title: 'JWT uses alg=none',
  what: 'A JSON Web Token in this exchange declares alg: "none", meaning it carries no signature at all.',
  why: 'A token with alg=none is unsigned. Any client can change the payload (for example set role to admin or sub to another user) and the server has no cryptographic way to notice. This is one of the classic JWT vulnerabilities.',
  attack:
    'The attacker decodes their own token, replaces the payload with {"sub":"admin","role":"admin"}, sets alg to "none" and re-encodes it. A naive verifier accepts it and grants admin access.',
  tags: ['jwt', 'auth', 'critical'],
  appliesTo: 'response',
  remediation: remediation(
    `// jsonwebtoken: pin the algorithm, never trust the token header
import jwt from 'jsonwebtoken';

const payload = jwt.verify(token, process.env.JWT_SECRET!, {
  algorithms: ['HS256'],   // explicit allow-list
  issuer: 'https://app.example.com',
  audience: 'app.example.com',
});`,
    `// jose: algorithms are mandatory
import { jwtVerify } from 'jose';

const { payload } = await jwtVerify(token, secret, {
  algorithms: ['HS256'],
  issuer: 'https://app.example.com',
});`,
    `# nginx cannot verify JWTs by itself; use auth_request to a service that
# pins algorithms, or the ngx_http_auth_jwt_module with an explicit alg.
auth_jwt_alg HS256;`,
  ),
  evaluate(ctx) {
    return ctx.jwts
      .filter((jwt) => (jwt.alg ?? '').toLowerCase() === 'none')
      .map((jwt) => ({
        key: `alg-none:${tokenKey(jwt.raw)}`,
        message: 'A JWT declares alg=none and is therefore unsigned.',
        detail: 'Reject tokens whose header algorithm is not on your allow-list. Decoded locally; not verified.',
        evidence: maskToken(jwt.raw),
      }));
  },
};

export default rule;
