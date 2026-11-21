import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './hsts-missing';

describe('header-hsts-missing', () => {
  it('flags HTTPS documents without HSTS', () => {
    expect(rule.evaluate(makeContext())).toHaveLength(1);
  });

  it('is quiet when HSTS is set', () => {
    expect(
      rule.evaluate(makeContext({ responseHeaders: { 'strict-transport-security': 'max-age=63072000' } })),
    ).toEqual([]);
  });

  it('does not apply to plain HTTP responses', () => {
    const ctx = makeContext({ url: 'http://app.example.com/', pageOrigin: 'http://app.example.com' });
    expect(rule.evaluate(ctx)).toEqual([]);
  });
});
