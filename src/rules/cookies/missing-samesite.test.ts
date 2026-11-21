import { describe, expect, it } from 'vitest';
import { cookie, makeContext } from '../../test-utils';
import rule from './missing-samesite';

describe('cookie-missing-samesite', () => {
  it('flags an absent SameSite attribute', () => {
    const hits = rule.evaluate(makeContext({}, [cookie({ sameSite: 'unspecified' })]));
    expect(hits).toHaveLength(1);
  });

  it('flags SameSite=None without Secure', () => {
    const hits = rule.evaluate(makeContext({}, [cookie({ sameSite: 'no_restriction', secure: false })]));
    expect(hits[0]?.message).toContain('SameSite=None without Secure');
  });

  it('accepts Lax, Strict and None+Secure', () => {
    expect(rule.evaluate(makeContext({}, [cookie({ sameSite: 'lax' })]))).toEqual([]);
    expect(rule.evaluate(makeContext({}, [cookie({ sameSite: 'no_restriction', secure: true })]))).toEqual([]);
  });
});
