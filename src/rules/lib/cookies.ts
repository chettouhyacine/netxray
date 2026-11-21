import { parseSameSite, parseSetCookie } from '../../core/headers';
import type { CookieObservation } from '../../core/types';
import type { RuleContext } from '../types';

export interface CookieFact {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'none' | 'lax' | 'strict' | 'unspecified';
  session: boolean;
  hostOnly: boolean;
  /** True when chrome.cookies supplied the fact (attributes are authoritative). */
  observed: boolean;
}

const SESSION_LIKE = /(session|sess|sid|auth|token|jwt|login|remember|connect\.sid)/i;

export function looksLikeSessionCookie(name: string): boolean {
  return SESSION_LIKE.test(name.replace(/^__Host-|^__Secure-/i, ''));
}

function fromObservation(cookie: CookieObservation): CookieFact {
  return {
    name: cookie.name,
    value: cookie.value,
    domain: cookie.domain,
    path: cookie.path,
    secure: cookie.secure,
    httpOnly: cookie.httpOnly,
    sameSite: cookie.sameSite === 'no_restriction' ? 'none' : cookie.sameSite,
    session: cookie.session,
    hostOnly: cookie.hostOnly,
    observed: true,
  };
}

function fromSetCookie(raw: string, ctx: RuleContext): CookieFact | null {
  const parsed = parseSetCookie(raw);
  if (!parsed.name) return null;
  const attributes = parsed.attributes;
  const domain =
    typeof attributes.domain === 'string'
      ? attributes.domain
      : ctx.event.pageOrigin.replace(/^https?:\/\//, '');
  const path = typeof attributes.path === 'string' ? attributes.path : '/';
  const maxAge = typeof attributes['max-age'] === 'string' ? Number(attributes['max-age']) : NaN;
  return {
    name: parsed.name,
    value: parsed.value,
    domain,
    path,
    secure: attributes.secure === true,
    httpOnly: attributes.httponly === true,
    sameSite: parseSameSite(typeof attributes.samesite === 'string' ? attributes.samesite : undefined),
    session: Number.isFinite(maxAge) && maxAge > 0 ? false : !attributes.expires,
    hostOnly: !attributes.domain,
    observed: false,
  };
}

/**
 * Returns the cookies that apply to the inspected page, preferring
 * chrome.cookies attributes and falling back to Set-Cookie headers when the
 * extension has no cookie access for that host.
 */
export function cookieFacts(ctx: RuleContext): CookieFact[] {
  if (ctx.cookies.length > 0) return ctx.cookies.map(fromObservation);
  return ctx.event.setCookie
    .map((raw) => fromSetCookie(raw, ctx))
    .filter((cookie): cookie is CookieFact => cookie !== null);
}

/** True when the page itself is served over HTTPS (cookie flags only matter then). */
export function pageIsSecure(ctx: RuleContext): boolean {
  return ctx.page.isHttps || ctx.event.pageOrigin.startsWith('https://');
}
