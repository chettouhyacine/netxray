import { findSecretsInText, maskSecret } from '../../core/redact';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'secret-in-response',
  severity: 'high',
  title: 'Secret exposed in a response body',
  what: 'A response body contains something that looks like a real credential: a cloud key, API token, private key, database URL or JWT.',
  why: 'Anything the browser receives is readable by the user, by extensions and by any script on the page. Secrets in API responses leak through screenshots, HAR files and browser caches even when the app UI never shows them.',
  attack:
    'An attacker who gets one HAR export, one browser extension with network access, or one XSS payload reads the leaked key and uses it directly against the cloud provider, outside your application’s controls.',
  tags: ['leaks', 'secrets'],
  appliesTo: 'response',
  remediation: remediation(
    `// Express: never serialize secrets. Shape responses explicitly.
res.json({
  id: user.id,
  name: user.name,
  email: user.email,
  // do not spread the whole row: ...user leaks passwordHash, apiKey, ...
});

// Store provider keys server-side only and read them from env.`,
    `// Next.js: select only public fields before returning
const user = await db.user.findUnique({ where: { id }, select: { id: true, name: true, email: true } });
return Response.json(user);`,
    `# nginx: strip accidental debug headers, but secrets in bodies must be fixed in code
proxy_hide_header X-Powered-By;`,
  ),
  evaluate(ctx) {
    const body = ctx.event.responseBodyText;
    if (!body) return [];
    return findSecretsInText(body).map((match) => ({
      key: `${match.kind}:${match.value.slice(0, 8)}`,
      message: `${match.label} found in the response body.`,
      detail: 'Treat this value as compromised: rotate it and remove it from the response.',
      evidence: maskSecret(match.value),
    }));
  },
};

export default rule;
