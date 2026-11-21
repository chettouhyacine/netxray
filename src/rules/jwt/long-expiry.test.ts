import { describe, expect, it } from 'vitest';
import { makeContext, makeJwt } from '../../test-utils';
import rule from './long-expiry';

describe('jwt-long-expiry', () => {
  it('flags a one-year token', () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeJwt({ alg: 'HS256' }, { sub: 'x', iat: now, exp: now + 365 * 24 * 3600 });
    const hits = rule.evaluate(makeContext({ responseBodyText: token }));
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toContain('365');
  });

  it('accepts a 15-minute token', () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeJwt({ alg: 'HS256' }, { sub: 'x', iat: now, exp: now + 900 });
    expect(rule.evaluate(makeContext({ responseBodyText: token }))).toEqual([]);
  });
});
