import { describe, expect, it } from 'vitest';
import {
  cacheControlDirectives,
  collectSetCookies,
  getHeader,
  hasHeader,
  hasToken,
  headerMap,
  parseRequestCookies,
  parseSameSite,
  parseSetCookie,
} from './headers';

describe('headerMap', () => {
  it('lower-cases names and joins duplicates', () => {
    const map = headerMap([
      { name: 'Content-Type', value: 'text/html' },
      { name: 'x-test', value: 'a' },
      { name: 'X-Test', value: 'b' },
    ]);
    expect(map['content-type']).toBe('text/html');
    expect(map['x-test']).toBe('a, b');
    expect(getHeader(map, 'CONTENT-TYPE')).toBe('text/html');
    expect(hasHeader(map, 'X-Test')).toBe(true);
    expect(hasHeader(map, 'missing')).toBe(false);
  });

  it('ignores malformed entries', () => {
    expect(headerMap(undefined)).toEqual({});
  });
});

describe('parseSetCookie', () => {
  it('parses name, value and attributes', () => {
    const cookie = parseSetCookie('sid=abc123; Path=/; HttpOnly; Secure; SameSite=None');
    expect(cookie.name).toBe('sid');
    expect(cookie.value).toBe('abc123');
    expect(cookie.attributes.httponly).toBe(true);
    expect(cookie.attributes.secure).toBe(true);
    expect(cookie.attributes.samesite).toBe('None');
    expect(cookie.attributes.path).toBe('/');
  });

  it('handles a bare cookie and an empty value', () => {
    expect(parseSetCookie('feature=').attributes).toEqual({});
    expect(parseSetCookie('name=value').name).toBe('name');
  });
});

describe('collectSetCookies', () => {
  it('collects every Set-Cookie header in order', () => {
    const cookies = collectSetCookies([
      { name: 'Set-Cookie', value: 'a=1' },
      { name: 'content-type', value: 'text/html' },
      { name: 'set-cookie', value: 'b=2' },
    ]);
    expect(cookies).toEqual(['a=1', 'b=2']);
  });
});

describe('parseRequestCookies', () => {
  it('splits a Cookie header', () => {
    const cookies = parseRequestCookies('a=1; b=two; broken');
    expect(cookies.map((cookie) => `${cookie.name}=${cookie.value}`)).toEqual(['a=1', 'b=two', 'broken=']);
  });

  it('returns nothing for an absent header', () => {
    expect(parseRequestCookies(undefined)).toEqual([]);
  });
});

describe('SameSite and Cache-Control', () => {
  it('normalises SameSite values', () => {
    expect(parseSameSite('None')).toBe('none');
    expect(parseSameSite('Lax')).toBe('lax');
    expect(parseSameSite('STRICT')).toBe('strict');
    expect(parseSameSite(undefined)).toBe('unspecified');
    expect(parseSameSite('garbage')).toBe('unspecified');
  });

  it('tokenises directive lists', () => {
    expect(hasToken('max-age=0; includeSubDomains', 'includeSubDomains')).toBe(true);
    expect(hasToken('no-store, max-age=0', 'no-store')).toBe(true);
    expect(hasToken(undefined, 'no-store')).toBe(false);
  });

  it('parses Cache-Control', () => {
    expect(cacheControlDirectives('private, Max-Age=0')).toEqual(['private', 'max-age=0']);
    expect(cacheControlDirectives(undefined)).toEqual([]);
  });
});
