import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './hsts-weak';

function withHsts(value: string) {
  return makeContext({ responseHeaders: { 'strict-transport-security': value } });
}

describe('header-hsts-weak', () => {
  it('flags a short max-age', () => {
    const hits = rule.evaluate(withHsts('max-age=3600'));
    expect(hits.map((hit) => hit.key)).toContain('max-age');
  });

  it('flags missing includeSubDomains', () => {
    const hits = rule.evaluate(withHsts('max-age=63072000'));
    expect(hits.map((hit) => hit.key)).toEqual(['subdomains']);
  });

  it('accepts a strong policy', () => {
    expect(rule.evaluate(withHsts('max-age=63072000; includeSubDomains; preload'))).toEqual([]);
  });

  it('ignores missing headers and malformed max-age', () => {
    expect(rule.evaluate(makeContext())).toEqual([]);
    expect(rule.evaluate(withHsts('includeSubDomains'))[0]?.key).toBe('max-age');
  });
});
