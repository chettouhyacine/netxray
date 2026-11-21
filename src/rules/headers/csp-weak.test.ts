import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './csp-weak';

function withCsp(value: string) {
  return makeContext({ responseHeaders: { 'content-security-policy': value } });
}

describe('header-csp-weak', () => {
  it('flags unsafe-inline script sources', () => {
    const hits = rule.evaluate(withCsp("default-src 'self'; script-src 'self' 'unsafe-inline'"));
    expect(hits[0]?.message).toContain("'unsafe-inline'");
  });

  it('flags wildcards in default-src', () => {
    expect(rule.evaluate(withCsp("default-src *"))).toHaveLength(1);
  });

  it('accepts a strict policy and ignores a missing one', () => {
    expect(rule.evaluate(withCsp("default-src 'self'; script-src 'self' 'nonce-abc'"))).toEqual([]);
    expect(rule.evaluate(makeContext())).toEqual([]);
  });
});
