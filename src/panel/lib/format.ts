import { findSecretsInText, maskSecret } from '../../core/redact';

const MAX_RENDER_CHARS = 20_000;

/**
 * Masks recognized secrets in captured text before rendering or exporting it.
 * The raw text stays in memory only.
 */
export function redactBody(text: string | undefined): string {
  if (!text) return '';
  let result = text;
  for (const match of findSecretsInText(text)) {
    if (!match.value) continue;
    result = result.split(match.value).join(maskSecret(match.value));
  }
  return result.slice(0, MAX_RENDER_CHARS);
}

export function bodyWasTruncated(text: string | undefined, truncated: boolean | undefined): boolean {
  return Boolean(truncated) || Boolean(text && text.length > MAX_RENDER_CHARS);
}

export interface CookieRisk {
  label: string;
  tone: 'high' | 'medium' | 'low';
}

export function cookieRisks(cookie: {
  httpOnly: boolean;
  secure: boolean;
  sameSite: string;
  hostOnly: boolean;
}): CookieRisk[] {
  const risks: CookieRisk[] = [];
  if (!cookie.httpOnly) risks.push({ label: 'JS-readable', tone: 'medium' });
  if (!cookie.secure) risks.push({ label: 'No Secure', tone: 'medium' });
  if (cookie.sameSite === 'unspecified' || cookie.sameSite === 'no_restriction') {
    risks.push({ label: 'No SameSite', tone: 'low' });
  }
  if (!cookie.hostOnly) risks.push({ label: 'Subdomain-wide', tone: 'low' });
  return risks;
}

/** Headers whose values must be masked by default. */
export function isSensitiveHeader(name: string): boolean {
  return /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token)$/i.test(name);
}
