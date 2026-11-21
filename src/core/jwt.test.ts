import { describe, expect, it } from 'vitest';
import { decodeJwt, findJwts, isJwt, sensitiveClaims } from './jwt';

function base64url(value: unknown): string {
  const json = JSON.stringify(value);
  return Buffer.from(json, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function makeJwt(header: unknown, payload: unknown, signature = 'sig'): string {
  return `${base64url(header)}.${base64url(payload)}.${signature}`;
}

describe('decodeJwt', () => {
  it('decodes header and payload', () => {
    const token = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'user-1', exp: 1_900_000_000, iat: 1_800_000_000 });
    const decoded = decodeJwt(token);
    expect(decoded?.alg).toBe('HS256');
    expect(decoded?.payload?.sub).toBe('user-1');
    expect(decoded?.expiresAt).toBe(1_900_000_000_000);
    expect(decoded?.issuedAt).toBe(1_800_000_000_000);
  });

  it('supports alg=none tokens with an empty signature', () => {
    const token = makeJwt({ alg: 'none' }, { sub: 'admin' }, '');
    const decoded = decodeJwt(token);
    expect(decoded?.alg).toBe('none');
    expect(decoded?.signature).toBe('');
  });

  it('reports missing exp as null', () => {
    const decoded = decodeJwt(makeJwt({ alg: 'HS256' }, { sub: 'x' }));
    expect(decoded?.expiresAt).toBeNull();
  });

  it('returns null for non-JWT input', () => {
    expect(decodeJwt('not-a-token')).toBeNull();
    expect(decodeJwt('')).toBeNull();
    expect(decodeJwt('a.b.c')).toBeNull();
  });

  it('reports decode errors for a valid-looking but corrupt payload', () => {
    const corruptPayload = Buffer.from('{not json', 'utf8')
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const token = `eyJhbGciOiJIUzI1NiJ9.${corruptPayload}.sig`;
    expect(decodeJwt(token)?.error).toBe('Could not decode JWT payload');
  });

  it('reports header decode errors', () => {
    const corruptHeader = Buffer.from('{"alg":', 'utf8')
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const token = `${corruptHeader}.${base64url({ sub: 'x' })}.sig`;
    expect(decodeJwt(token)?.error).toBe('Could not decode JWT header');
  });
});

describe('isJwt / findJwts', () => {
  it('recognises and extracts tokens from text', () => {
    const token = makeJwt({ alg: 'HS256' }, { sub: 'x' });
    expect(isJwt(token)).toBe(true);
    expect(findJwts(`Authorization: Bearer ${token}`)).toEqual([token]);
    expect(findJwts(`duplicate ${token} ${token}`)).toHaveLength(1);
  });

  it('ignores unrelated strings', () => {
    expect(findJwts('hello world')).toEqual([]);
    expect(isJwt('eyJhbGciOiJIUzI1NiJ9')).toBe(false);
  });
});

describe('sensitiveClaims', () => {
  it('finds forbidden claims', () => {
    expect(sensitiveClaims({ sub: 'x', password: 'hunter2', api_key: 'k' })).toEqual(['password', 'api_key']);
    expect(sensitiveClaims(null)).toEqual([]);
  });
});
