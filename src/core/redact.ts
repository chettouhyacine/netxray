/**
 * Redaction for anything rendered in the UI.
 *
 * The extension is local-only, but a screenshot or shoulder-surf while pair
 * programming should not leak session tokens. Values stay in memory; only the
 * rendered string is masked, and the user can reveal it deliberately.
 */

const SECRET_KEY_PATTERN =
  /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-csrf-token|x-xsrf-token)$/i;

/** Query/body parameter names that commonly carry credentials. */
export const SENSITIVE_NAME_PATTERN =
  /(token|secret|password|passwd|pwd|api[_-]?key|apikey|access[_-]?key|auth|session|sig|signature|credential|jwt|code)$/i;

export function isSensitiveName(name: string): boolean {
  return SENSITIVE_NAME_PATTERN.test(name.replace(/[[\].]/g, ''));
}

/** Keeps the first and last four characters so a value is still recognisable. */
export function maskSecret(value: string): string {
  if (!value) return '';
  const trimmed = value.trim();
  if (trimmed.length <= 12) return '•'.repeat(Math.min(12, Math.max(4, trimmed.length)));
  return `${trimmed.slice(0, 4)}${'•'.repeat(Math.min(24, trimmed.length - 8))}${trimmed.slice(-4)}`;
}

/** Masks values of sensitive query parameters and removes URL userinfo. */
export function redactUrl(raw: string): string {
  try {
    const url = new URL(raw);
    if (url.username || url.password) {
      url.username = url.username ? 'redacted' : '';
      url.password = url.password ? 'redacted' : '';
    }
    for (const key of Array.from(new Set(url.searchParams.keys()))) {
      if (!isSensitiveName(key)) continue;
      const values = url.searchParams.getAll(key).map(maskSecret);
      url.searchParams.delete(key);
      for (const value of values) url.searchParams.append(key, value);
    }
    return url.toString();
  } catch {
    return raw;
  }
}

/** Masks credential-bearing request/response header values. */
export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    result[key] = redactHeaderValue(key, value);
  }
  return result;
}

export function redactHeaderValue(name: string, value: string): string {
  if (SECRET_KEY_PATTERN.test(name)) {
    if (/^set-cookie$/i.test(name)) {
      return value.replace(/(^|[;,]\s*)([^=;,\s]+)=([^;]*)/g, (_match, prefix: string, key: string, val: string) =>
        isSensitiveName(key) ? `${prefix}${key}=${maskSecret(val)}` : `${prefix}${key}=${val}`,
      );
    }
    if (/^cookie$/i.test(name)) {
      return value
        .split(';')
        .map((part) => {
          const eq = part.indexOf('=');
          if (eq < 0) return part.trim();
          const key = part.slice(0, eq).trim();
          const val = part.slice(eq + 1).trim();
          return isSensitiveName(key) ? `${key}=${maskSecret(val)}` : `${key}=${val}`;
        })
        .join('; ');
    }
    if (/^authorization$/i.test(name)) {
      const [scheme, ...rest] = value.split(' ');
      if (rest.length > 0) return `${scheme} ${maskSecret(rest.join(' '))}`;
    }
    return maskSecret(value);
  }
  return value;
}

export interface SecretMatch {
  kind: string;
  value: string;
  label: string;
}

const BODY_SECRET_PATTERNS: { kind: string; label: string; pattern: RegExp }[] = [
  { kind: 'aws-access-key', label: 'AWS access key id', pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { kind: 'github-token', label: 'GitHub token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { kind: 'stripe-key', label: 'Stripe secret key', pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { kind: 'openai-key', label: 'API key (sk-…)', pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { kind: 'slack-token', label: 'Slack token', pattern: /\bxox[abopr]-[A-Za-z0-9-]{10,}\b/g },
  { kind: 'private-key', label: 'Private key block', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  // JWTs are deliberately not treated as leaked secrets: a token endpoint
  // returning a correctly signed token is normal. The jwt-* rules inspect the
  // token's algorithm, lifetime and claims instead.
  { kind: 'database-url', label: 'Database connection string', pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s"'<>]+/g },
];

/** Finds well-known secret shapes in text (response bodies, headers). */
export function findSecretsInText(text: string, limit = 20): SecretMatch[] {
  if (!text) return [];
  const matches: SecretMatch[] = [];
  const seen = new Set<string>();
  for (const { kind, label, pattern } of BODY_SECRET_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null && matches.length < limit) {
      const value = match[0];
      if (seen.has(value)) continue;
      seen.add(value);
      matches.push({ kind, label, value });
    }
  }
  return matches;
}
