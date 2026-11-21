import { describe, expect, it } from 'vitest';
import {
  hostOf,
  isHttpUrl,
  isHttpsUrl,
  isLocalHost,
  isThirdParty,
  originOf,
  pathOf,
  queryOf,
  registrableDomain,
  safeUrl,
} from './url';

describe('safe URL helpers', () => {
  it('parses valid URLs', () => {
    expect(hostOf('https://App.Example.com/a')).toBe('app.example.com');
    expect(originOf('https://app.example.com/a?b=1')).toBe('https://app.example.com');
    expect(pathOf('https://app.example.com/a?b=1')).toBe('/a?b=1');
    expect(queryOf('https://app.example.com/?a=1&a=2&b=3')).toEqual({ a: ['1', '2'], b: ['3'] });
  });

  it('degrades gracefully on malformed input', () => {
    expect(safeUrl('nope')).toBeNull();
    expect(hostOf('nope')).toBe('');
    expect(queryOf('nope')).toEqual({});
    expect(pathOf('nope')).toBe('nope');
  });

  it('classifies protocols and local hosts', () => {
    expect(isHttpsUrl('https://a.test')).toBe(true);
    expect(isHttpUrl('http://a.test')).toBe(true);
    expect(isHttpUrl('https://a.test')).toBe(false);
    expect(isLocalHost('localhost')).toBe(true);
    expect(isLocalHost('app.localhost')).toBe(true);
    expect(isLocalHost('example.com')).toBe(false);
  });
});

describe('registrableDomain', () => {
  it('returns the registrable domain', () => {
    expect(registrableDomain('docs.example.com')).toBe('example.com');
    expect(registrableDomain('example.com')).toBe('example.com');
    expect(registrableDomain('www.example.co.uk')).toBe('example.co.uk');
  });
});

describe('isThirdParty', () => {
  it('compares registrable domains', () => {
    expect(isThirdParty('https://api.example.com/x', 'https://app.example.com')).toBe(false);
    expect(isThirdParty('https://cdn.other.com/x', 'https://app.example.com')).toBe(true);
    expect(isThirdParty('https://cdn.other.com/x', '')).toBe(false);
  });
});
