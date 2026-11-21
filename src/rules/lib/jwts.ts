import { decodeJwt, findJwts, type DecodedJwt } from '../../core/jwt';
import type { NetworkEvent } from '../../core/types';

/**
 * Gathers JWT-looking strings from the URL, headers, cookies and both bodies.
 * Decoding happens locally and tokens are never logged.
 */
export function collectJwts(event: NetworkEvent): DecodedJwt[] {
  const candidates = new Set<string>();

  const add = (text: string | undefined): void => {
    if (!text) return;
    for (const token of findJwts(text)) candidates.add(token);
  };

  add(event.url);
  add(event.requestHeaders.authorization);
  add(event.requestHeaders.cookie);
  add(event.responseHeaders['set-cookie']);
  add(event.requestBodyText);
  add(event.responseBodyText);

  const decoded: DecodedJwt[] = [];
  for (const token of candidates) {
    const jwt = decodeJwt(token);
    if (jwt) decoded.push(jwt);
  }
  return decoded;
}

/** Stable short hash so identical tokens dedupe across requests. */
export function tokenKey(token: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < token.length; i += 1) {
    hash ^= token.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

/** Masks a token for evidence display. */
export function maskToken(token: string): string {
  if (token.length <= 24) return `${token.slice(0, 6)}…`;
  return `${token.slice(0, 12)}…${token.slice(-6)}`;
}
