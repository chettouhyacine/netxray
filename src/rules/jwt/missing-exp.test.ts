import { describe, expect, it } from 'vitest';
import { makeContext, makeJwt } from '../../test-utils';
import rule from './missing-exp';

describe('jwt-missing-exp', () => {
  it('flags tokens without exp', () => {
    const token = makeJwt({ alg: 'HS256' }, { sub: 'x' });
    expect(rule.evaluate(makeContext({ responseBodyText: token }))).toHaveLength(1);
  });

  it('accepts tokens with exp and ignores non-JWT bodies', () => {
    const token = makeJwt({ alg: 'HS256' }, { sub: 'x', exp: 2_000_000_000 });
    expect(rule.evaluate(makeContext({ responseBodyText: token }))).toEqual([]);
    expect(rule.evaluate(makeContext({ responseBodyText: 'no tokens here' }))).toEqual([]);
  });
});
