import { describe, expect, it } from 'vitest';
import { makeContext, makeJwt } from '../../test-utils';
import rule from './secret-in-url';

describe('secret-in-url', () => {
  it('flags sensitive query parameters', () => {
    const hits = rule.evaluate(
      makeContext({ url: 'https://app.example.com/reset?token=abcdef123456789&q=help' }),
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]?.key).toBe('query:token');
    expect(hits[0]?.evidence).not.toBe('abcdef123456789');
  });

  it('flags JWTs in any query parameter', () => {
    const token = makeJwt({ alg: 'HS256' }, { sub: 'user' });
    const hits = rule.evaluate(makeContext({ url: `https://app.example.com/sso?assertion=${token}` }));
    expect(hits[0]?.message).toContain('JWT');
  });

  it('ignores placeholders, short values and innocuous params', () => {
    expect(rule.evaluate(makeContext({ url: 'https://app.example.com/?token=null' }))).toEqual([]);
    expect(rule.evaluate(makeContext({ url: 'https://app.example.com/?token=1' }))).toEqual([]);
    expect(rule.evaluate(makeContext({ url: 'https://app.example.com/?q=hello' }))).toEqual([]);
  });
});
