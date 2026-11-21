/**
 * Client-side-only JWT decoding. Nothing is verified: verification requires a
 * key we do not have and should not collect. The UI labels every decoded token
 * as "decoded, not verified".
 */

export interface DecodedJwt {
  raw: string;
  header: Record<string, unknown> | null;
  payload: Record<string, unknown> | null;
  signature: string;
  alg: string | null;
  expiresAt: number | null;
  issuedAt: number | null;
  notBefore: number | null;
  error?: string;
}

const BASE64_URL = /^[A-Za-z0-9_-]*$/;

function decodeBase64Url(input: string): string {
  if (!BASE64_URL.test(input)) throw new Error('invalid base64url');
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  let binary: string;
  if (typeof atob === 'function') {
    binary = atob(padded);
  } else {
    binary = Buffer.from(padded, 'base64').toString('binary');
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

export function isJwt(value: string): boolean {
  if (!value || value.length < 20) return false;
  const parts = value.split('.');
  if (parts.length !== 3) return false;
  if (!parts[0]?.startsWith('eyJ')) return false;
  return parts.every((part) => part === '' || BASE64_URL.test(part));
}

/** Decodes header and payload; returns null when the token is not a JWT. */
export function decodeJwt(token: string): DecodedJwt | null {
  const trimmed = token.trim();
  if (!isJwt(trimmed)) return null;
  const [rawHeader, rawPayload, signature = ''] = trimmed.split('.');
  const result: DecodedJwt = {
    raw: trimmed,
    header: null,
    payload: null,
    signature,
    alg: null,
    expiresAt: null,
    issuedAt: null,
    notBefore: null,
  };
  try {
    if (rawHeader) {
      const header = JSON.parse(decodeBase64Url(rawHeader)) as Record<string, unknown>;
      result.header = header;
      result.alg = typeof header.alg === 'string' ? header.alg : null;
    }
  } catch {
    result.error = 'Could not decode JWT header';
    return result;
  }
  try {
    if (rawPayload) {
      const payload = JSON.parse(decodeBase64Url(rawPayload)) as Record<string, unknown>;
      result.payload = payload;
      result.expiresAt = numericClaim(payload.exp);
      result.issuedAt = numericClaim(payload.iat);
      result.notBefore = numericClaim(payload.nbf);
    }
  } catch {
    result.error = 'Could not decode JWT payload';
  }
  return result;
}

function numericClaim(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value * 1000;
  if (typeof value === 'string' && /^\d+$/.test(value)) return Number(value) * 1000;
  return null;
}

/** Returns every JWT-looking substring in a blob of text. */
export function findJwts(text: string, limit = 20): string[] {
  if (!text) return [];
  const matches = text.match(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g) ?? [];
  return Array.from(new Set(matches)).slice(0, limit);
}

/** Payload keys that should never travel inside a client-readable token. */
export const SENSITIVE_JWT_CLAIMS = [
  'password',
  'passwd',
  'pwd',
  'secret',
  'ssn',
  'creditcard',
  'credit_card',
  'cardnumber',
  'card_number',
  'cvv',
  'api_key',
  'apiKey',
  'private_key',
  'privateKey',
  'access_token',
  'refresh_token',
];

export function sensitiveClaims(payload: Record<string, unknown> | null): string[] {
  if (!payload) return [];
  return SENSITIVE_JWT_CLAIMS.filter((claim) => claim in payload);
}
