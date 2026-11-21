import type { HeaderEntry, RawCookie } from './types';

/**
 * Case-insensitive header helpers.
 */
export function headerMap(headers: HeaderEntry[] | undefined): Record<string, string> {
  const map: Record<string, string> = {};
  for (const header of headers ?? []) {
    if (!header || typeof header.name !== 'string') continue;
    const key = header.name.toLowerCase();
    const value = typeof header.value === 'string' ? header.value : '';
    map[key] = map[key] ? `${map[key]}, ${value}` : value;
  }
  return map;
}

export function getHeader(headers: Record<string, string>, name: string): string | undefined {
  return headers[name.toLowerCase()];
}

export function hasHeader(headers: Record<string, string>, name: string): boolean {
  return Object.prototype.hasOwnProperty.call(headers, name.toLowerCase());
}

/** True when a token appears as a directive in a comma/semicolon separated value. */
export function hasToken(value: string | undefined, token: string): boolean {
  if (!value) return false;
  return value
    .split(/[,;]/)
    .map((part) => part.trim().toLowerCase())
    .some((part) => part === token.toLowerCase() || part.startsWith(`${token.toLowerCase()} `));
}

/**
 * SameSite is more subtle than a token check: `SameSite=None` needs `Secure`,
 * and an absent attribute is treated as `unspecified`.
 */
export function parseSameSite(value: string | undefined): 'none' | 'lax' | 'strict' | 'unspecified' {
  const normalized = (value ?? '').trim().toLowerCase();
  if (normalized === 'none' || normalized === 'no_restriction') return 'none';
  if (normalized === 'lax') return 'lax';
  if (normalized === 'strict') return 'strict';
  return 'unspecified';
}

/**
 * Parses a single Set-Cookie header. Attribute names are lower-cased; bare
 * attributes (Secure, HttpOnly) are stored as `true`.
 */
export function parseSetCookie(raw: string): RawCookie {
  const [pair, ...attributeParts] = raw.split(';');
  const separator = (pair ?? '').indexOf('=');
  const name = separator >= 0 ? (pair ?? '').slice(0, separator).trim() : (pair ?? '').trim();
  const value = separator >= 0 ? (pair ?? '').slice(separator + 1).trim() : '';
  const attributes: Record<string, string | true> = {};

  for (const part of attributeParts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) {
      attributes[trimmed.toLowerCase()] = true;
    } else {
      attributes[trimmed.slice(0, eq).trim().toLowerCase()] = trimmed.slice(eq + 1).trim();
    }
  }

  return { name, value, attributes };
}

/** All Set-Cookie header values from a HAR header list (order preserved). */
export function collectSetCookies(headers: HeaderEntry[] | undefined): string[] {
  return (headers ?? [])
    .filter((header) => header.name.toLowerCase() === 'set-cookie')
    .map((header) => header.value);
}

/** Parses request cookies from a Cookie header value. */
export function parseRequestCookies(cookieHeader: string | undefined): RawCookie[] {
  if (!cookieHeader) return [];
  return cookieHeader
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const eq = part.indexOf('=');
      return {
        name: (eq >= 0 ? part.slice(0, eq) : part).trim(),
        value: eq >= 0 ? part.slice(eq + 1).trim() : '',
        attributes: {},
      };
    });
}

/** Splits a Cache-Control header into lower-cased directives. */
export function cacheControlDirectives(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((part) => part.trim().toLowerCase())
    .filter(Boolean);
}
